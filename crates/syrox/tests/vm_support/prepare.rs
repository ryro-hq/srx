use super::{
    Result,
    common::{self},
    host,
    process::Control,
};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub const FIRMWARE_REVISION: &str = "cf4c22b9f05c680928e6d96a9d198f5845573a87";

/// Build the SDK's guest kernel with Landlock enabled, without host package or
/// policy changes. Existing source edits must be exactly our checked patch.
pub fn firmware() -> Result<PathBuf> {
    let root = super::config::root();
    let source = root.join("target/libkrunfw-source");
    let evidence = root
        .join("target/firmware-evidence")
        .join(host::run_id()?);
    common::private(&evidence)?;
    let control = Control::new(None)?;
    if !source.exists() {
        super::process::command(
            Command::new("git")
                .args([
                    "clone",
                    "--no-checkout",
                    "https://github.com/superradcompany/libkrunfw.git",
                ])
                .arg(&source),
            &evidence.join("clone.log"),
            Duration::from_mins(5),
            &control,
        )?;
    }
    super::process::command(
        Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["fetch", "origin", FIRMWARE_REVISION]),
        &evidence.join("fetch.log"),
        Duration::from_mins(5),
        &control,
    )?;
    super::process::command(
        Command::new("git").arg("-C").arg(&source).args([
            "checkout",
            "--detach",
            FIRMWARE_REVISION,
        ]),
        &evidence.join("checkout.log"),
        Duration::from_mins(1),
        &control,
    )?;
    let config = configure(&source, &evidence, &control)?;
    fs::write(
        source.join(".dockerignore"),
        ".git\nlinux-*\n*.so*\nkernel.c\ntarballs\n",
    )?;
    let directory = root.join("target/vm-runtime/landlock");
    let recipe = root.join("tests/vm/firmware.Containerfile");
    super::process::command(
        Command::new("docker")
            .arg("build")
            .arg("--output")
            .arg(format!("type=local,dest={}", directory.display()))
            .arg("-f")
            .arg(&recipe)
            .arg(&source),
        &evidence.join("build.log"),
        Duration::from_hours(1),
        &control,
    )?;
    let binary = directory.join("libkrunfw.so.5.6.1");
    common::save(
        &directory.join("provenance.json"),
        &json!({
            "sdk":common::SDK_VERSION,"repository":"https://github.com/superradcompany/libkrunfw.git",
            "revision":FIRMWARE_REVISION,"kernel":"6.12.109",
            "kernel_tarball_sha256":"e81af28f5941db1c7f356151dfbab2ca5786c8be76474f7d42ea306cdeb445cd",
            "source_config_sha256":super::snapshot::digest(&config)?,
            "kernel_config_sha256":super::snapshot::digest(&directory.join("kernel.config"))?,
            "recipe_sha256":super::snapshot::digest(&recipe)?,"firmware_sha256":super::snapshot::digest(&binary)?,"evidence":evidence,
            "changes":["CONFIG_SECURITY_LANDLOCK=y","landlock added to CONFIG_LSM"],
            "qualification":"not implied by successful compilation; guest probes required"
        }),
    )?;
    Ok(binary)
}

fn configure(
    source: &std::path::Path,
    evidence: &std::path::Path,
    control: &Control,
) -> Result<PathBuf> {
    let original = super::process::command(
        Command::new("git").arg("-C").arg(source).args([
            "show",
            &format!("{FIRMWARE_REVISION}:config-libkrunfw_x86_64"),
        ]),
        &evidence.join("upstream-config.log"),
        Duration::from_mins(1),
        control,
    )?;
    let dirty = super::process::command(
        Command::new("git")
            .arg("-C")
            .arg(source)
            .args(["diff", "--name-only"]),
        &evidence.join("dirty-inputs.log"),
        Duration::from_mins(1),
        control,
    )?;
    let new = super::process::command(
        Command::new("git").arg("-C").arg(source).args([
            "ls-files",
            "--others",
            "--exclude-standard",
        ]),
        &evidence.join("new-inputs.log"),
        Duration::from_mins(1),
        control,
    )?;
    if dirty
        .lines()
        .any(|name| name != "config-libkrunfw_x86_64")
        || new.lines().any(|name| name != ".dockerignore")
    {
        return Err("firmware checkout has unrelated local inputs".into());
    }
    let desired = original
        .replace(
            "# CONFIG_SECURITY_LANDLOCK is not set",
            "CONFIG_SECURITY_LANDLOCK=y",
        )
        .replace("CONFIG_LSM=\"", "CONFIG_LSM=\"landlock,");
    let config = source.join("config-libkrunfw_x86_64");
    let current = fs::read_to_string(&config)?;
    if current != original && current != desired {
        return Err("firmware configuration has unrelated local changes".into());
    }
    fs::write(&config, desired)?;
    let patch = super::process::command(
        Command::new("git")
            .arg("-C")
            .arg(source)
            .args(["diff", "--", "config-libkrunfw_x86_64"]),
        &evidence.join("config-diff.log"),
        Duration::from_mins(1),
        control,
    )?;
    fs::write(evidence.join("landlock.patch"), patch)?;
    Ok(config)
}

pub fn main(arguments: &[String]) -> Result<()> {
    let control = Control::new(std::env::var_os("SYROX_VM_CANCEL_FILE").map(PathBuf::from))?;
    common::private(&super::config::root().join("target/vm-cache"))?;
    let _lock = host::lock(
        &super::config::root().join("target/vm-cache/execution.lock"),
        &control,
    )?;
    let mut args = arguments.to_vec();
    if args.iter().any(|value| value == "--help") {
        println!(
            "cargo test --locked --test vm -- --prepare [--install-runtime] [--build-firmware] [--image REGISTRY/IMAGE@sha256:DIGEST | --image-archive /absolute/guest.tar] [--runtime /absolute/msb --firmware /absolute/libkrunfw.so] [--preparation-image IMAGE@sha256:DIGEST | sha256:IMAGE_ID]\nWithout inputs, diagnose the saved configuration and KVM. --install-runtime downloads 0.7.3 only into target/vm-runtime. --build-firmware builds the SDK kernel with Landlock using Docker. Pins and diagnostics are stored in target/."
        );
        return Ok(());
    }
    if let Some(index) = args
        .iter()
        .position(|value| value == "--build-firmware")
    {
        args.remove(index);
        if args.iter().any(|value| value == "--firmware") {
            return Err("choose --build-firmware or --firmware".into());
        }
        let firmware = firmware()?;
        args.extend([
            "--firmware".into(),
            firmware.to_string_lossy().into_owned(),
        ]);
    }
    if let Some(index) = args
        .iter()
        .position(|value| value == "--install-runtime")
    {
        args.remove(index);
        let runtime = tokio::runtime::Runtime::new()?;
        let home = super::config::root().join("target/vm-runtime");
        let backend = microsandbox::LocalBackend::builder()
            .home(&home)
            .config_path(home.join("settings.json"))
            .build_lazy()?;
        let pair = runtime.block_on(control.bounded(
            "runtime installation",
            Duration::from_mins(10),
            microsandbox::setup::ensure_runtime(
                backend.config(),
                microsandbox::setup::InstallOptions {
                    version: common::SDK_VERSION.into(),
                    ..Default::default()
                },
            ),
        ))?;
        let pins = serde_json::json!({"runtime":pair.msb_path,"firmware":pair.libkrunfw_path,
            "runtime_sha256":super::snapshot::digest(&pair.msb_path)?,"firmware_sha256":super::snapshot::digest(&pair.libkrunfw_path)?});
        common::save(&home.join("pins.json"), &pins)?;
        eprintln!(
            "Installed pinned runtime pair: {}",
            home.display()
        );
    }
    if !args.is_empty() {
        let mut values = std::collections::BTreeMap::new();
        let mut args = args.iter();
        while let Some(key) = args.next() {
            if ![
                "--image",
                "--image-archive",
                "--runtime",
                "--firmware",
                "--preparation-image",
            ]
            .contains(&key.as_str())
            {
                return Err(format!("unknown preparation option: {key}").into());
            }
            if values
                .insert(
                    key.clone(),
                    args.next().ok_or("missing option value")?.clone(),
                )
                .is_some()
            {
                return Err("duplicate preparation option".into());
            }
        }
        let installed: serde_json::Value =
            fs::read(super::config::root().join("target/vm-runtime/pins.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
        let runtime = PathBuf::from(
            values
                .get("--runtime")
                .map(String::as_str)
                .or_else(|| installed["runtime"].as_str())
                .ok_or("--runtime or --install-runtime required")?,
        )
        .canonicalize()?;
        let firmware = PathBuf::from(
            values
                .get("--firmware")
                .map(String::as_str)
                .or_else(|| installed["firmware"].as_str())
                .ok_or("--firmware or --install-runtime required")?,
        )
        .canonicalize()?;
        let image_archive = values
            .get("--image-archive")
            .map(PathBuf::from)
            .map(|path| path.canonicalize())
            .transpose()?;
        let image = if let Some(archive) = &image_archive {
            let rt = tokio::runtime::Runtime::new()?;
            let backend = rt.block_on(
                control.bounded(
                    "image backend preparation",
                    Duration::from_mins(2),
                    microsandbox::LocalBackend::builder()
                        .home(super::config::root().join("target/vm-cache/microsandbox"))
                        .config_path(super::config::root().join("target/vm-cache/sdk-config.json"))
                        .build(),
                ),
            )?;
            let images = rt.block_on(control.bounded(
                "image preparation",
                Duration::from_mins(5),
                microsandbox::Image::load_local(&backend, archive, Vec::new()),
            ))?;
            if images.is_empty() {
                return Err("image archive is empty".into());
            }
            format!(
                "docker.io/library/syrox-vm@{}",
                images[0]
                    .manifest_digest()
                    .ok_or("imported image manifest digest missing")?
            )
        } else {
            values
                .get("--image")
                .ok_or("--image or --image-archive required")?
                .clone()
        };
        let firmware_sha256 = super::snapshot::digest(&firmware)?;
        let firmware_provenance =
            fs::read(super::config::root().join("target/vm-runtime/landlock/provenance.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .filter(|value| value["firmware_sha256"] == firmware_sha256);
        let config = super::config::Config {
            sdk: common::SDK_VERSION.into(),
            image,
            preparation_image: values.get("--preparation-image").cloned(),
            runtime_sha256: super::snapshot::digest(&runtime)?,
            firmware_sha256,
            runtime,
            firmware,
            firmware_provenance,
            image_archive_sha256: image_archive
                .as_ref()
                .map(|path| super::snapshot::digest(path))
                .transpose()?,
            image_archive,
        };
        config.validate()?;
        if super::config::config_path().exists() {
            return Err("VM configuration already exists; review/edit its pins explicitly".into());
        }
        common::private(
            super::config::config_path()
                .parent()
                .ok_or("config parent")?,
        )?;
        common::save(&super::config::config_path(), &config)?;
    }
    common::private(&super::config::root().join("target/vm-cache"))?;
    let doctor = super::config::doctor();
    common::save(
        &super::config::root().join("target/vm-doctor.json"),
        &doctor,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({"doctor":doctor,
        "guest_qualification":"pending until cargo test --test vm succeeds"}))?
    );
    if doctor["ready"] != true {
        return Err(
            "VM preparation has unmet host requirements; inspect target/vm-doctor.json".into(),
        );
    }
    Ok(())
}

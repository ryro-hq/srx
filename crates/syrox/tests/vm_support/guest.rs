use super::{
    Result,
    common::{self, Gate},
    process::Control,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const GATE_TIMEOUT: Duration = Duration::from_mins(4);

pub fn main(args: &[String]) -> Result<()> {
    if args
        .first()
        .is_some_and(|value| value == "--measure")
    {
        return super::measure::serve(Path::new(
            args.get(1)
                .ok_or("measurement evidence directory required")?,
        ));
    }
    if args
        .first()
        .is_some_and(|value| value == "--delegated")
    {
        let input: Value = serde_json::from_slice(&fs::read(
            args.get(1)
                .ok_or("missing delegated gate input")?,
        )?)?;
        return delegated(&input);
    }
    let evidence = PathBuf::from(
        args.first()
            .ok_or("explicit guest evidence directory required")?,
    );
    if !evidence.is_absolute() || !Path::new("/sources/Cargo.lock").is_file() {
        return Err("guest source/evidence mounts required".into());
    }
    // Cargo starts integration targets in the package directory. Fixtures and
    // the captured build intentionally use the workspace root inside the VM.
    std::env::set_current_dir("/work/src")?;
    let control = Control::new(Some(evidence.join("cancel")))?;
    let selected: Vec<Gate> = serde_json::from_slice(&fs::read(evidence.join("selected.json"))?)?;
    let fault: Option<common::Fault> =
        serde_json::from_slice(&fs::read(evidence.join("fault.json"))?)?;
    let ecosystem = evidence.join("ecosystem-plan.json").is_file();
    let profile: super::resources::Profile =
        serde_json::from_slice(&fs::read(evidence.join("profile.json"))?)?;
    let native = profile == super::resources::Profile::Native;
    if native {
        if !selected.is_empty() || ecosystem || fault.is_some() {
            return Err("native profile cannot select acceptance gates or injected faults".into());
        }
    } else {
        common::validate_selection(&selected, ecosystem)?;
    }
    let mut report = json!({"status":"preparing","profile":profile,"selected":selected,"fault":fault,"gates":selected.iter().enumerate().map(|(index, gate)| json!({"name":gate.name,"package":gate.package,"target":gate.target,"status":"not_run","log":format!("gate-{index}.log"),"workspace":format!("/work/g{index}")})).collect::<Vec<_>>(),"qualification":"pending"});
    super::evidence::save(&evidence.join("guest-report.json"), &report)?;
    let outcome = (|| {
        let sources: Value =
            serde_json::from_slice(&fs::read(evidence.join("source-manifest.json"))?)?;
        let source_pins = serde_json::from_value(sources["files"].clone())?;
        super::snapshot::verify_files(Path::new("/work/src"), &source_pins)?;
        report["source_sha256"] = sources["sha256"].clone();
        let prepared_pins: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(evidence.join("prepared-pins.json"))?)?;
        for (path, pin) in &prepared_pins {
            if super::snapshot::digest(Path::new(path))? != *pin {
                return Err("prepared candidate changed before guest execution".into());
            }
        }
        let preparation: Value = serde_json::from_slice(&fs::read(
            evidence.join("preparation-report.json"),
        )?)?;
        report["build_environment"] = json!({"prepared_before_vm":true,"candidate_profile":"release","fixture_profile":"test","build_jobs":preparation["build_jobs"],"resource_policy":"host-inherited","debug_info":false,"incremental":false});
        qualify(&evidence, &control)?;
        report["qualification"] =
            json!("basic capabilities passed; core pidfs ioctl probe pending");
        let artifacts: BTreeMap<String, PathBuf> = serde_json::from_slice(&fs::read(
            evidence.join("prepared-artifacts.json"),
        )?)?;
        audit_registry(&artifacts, &evidence, &control)?;
        if fault == Some(common::Fault::MissingFixture) {
            fs::remove_file("tests/fixtures/session-payload.c")?;
        }
        let pinned = prepare_candidates(&artifacts, &evidence, &control)?;
        report["binaries"] = serde_json::to_value(&pinned)?;
        report["candidate_root"] = json!(common::GUEST_CANDIDATES);
        report["artifact_pins"] =
            serde_json::from_slice(&fs::read(evidence.join("artifact-pins.json"))?)?;
        if fault == Some(common::Fault::CandidateMutation) {
            let candidate = Path::new(common::GUEST_CANDIDATES).join("syrox-worker");
            fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
            let mut bytes = fs::read(&candidate)?;
            *bytes.last_mut().ok_or("empty worker candidate")? ^= 1;
            fs::write(candidate, bytes)?;
        }
        // Kernel names alone are insufficient: run the core's namespace
        // ioctl and independently opened pidfs identity test before any gate.
        let probe = common::gates()
            .into_iter()
            .find(|gate| {
                gate.name
                    .ends_with("::kernel_pidfs_identity_is_stable_across_independent_opens")
            })
            .ok_or("missing pidfs qualification gate")?;
        let engine = artifacts
            .get("syrox-engine/lib")
            .ok_or("missing engine libtest")?;
        let result = super::process::command(
            Command::new(engine).args([
                &probe.name,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]),
            &evidence.join("pidfs-qualification.log"),
            Duration::from_secs(20),
            &control,
        )?;
        common::require_one_passed(&result)?;
        report["qualification"] = json!(
            "passed: PID 1, non-root manager >=254, namespaces, pidfs ioctls, cgroup v2, PTY, Landlock >=6"
        );
        super::evidence::save(&evidence.join("guest-report.json"), &report)?;
        if native {
            common::private(Path::new("/work/native-tmp"))?;
            report["native"] = serde_json::to_value(super::native::run(
                &artifacts, &evidence, &control,
            )?)?;
            verify_candidates(&evidence, &pinned)?;
            verify_artifacts(&artifacts, &report["artifact_pins"])?;
            return Ok(());
        }
        let mut failures = 0_usize;
        for (index, gate) in selected.iter().enumerate() {
            control.check()?;
            verify_candidates(&evidence, &pinned)?;
            let workspace = Path::new("/work").join(format!("g{index}"));
            common::private(&workspace)?;
            let mut env = environment(&evidence, &workspace, &pinned)?;
            if fault == Some(common::Fault::TestFailure) {
                env.insert(
                    "SYROX_SYSTEMD_USER_BUS".into(),
                    "/run/user/1000/missing-gate-fixture-bus".into(),
                );
            }
            let binary = artifacts
                .get(&format!("{}/{}", gate.package, gate.target))
                .ok_or("required libtest fixture missing")?;
            let log = evidence.join(format!("gate-{index}.log"));
            report["gates"][index]["status"] = json!("running");
            super::evidence::save(&evidence.join("guest-report.json"), &report)?;
            println!("test {} ...", gate.label());
            super::measure::begin(&evidence, index)?;
            let started = std::time::Instant::now();
            let result = if fault == Some(common::Fault::Timeout) {
                let fixture = workspace.join("timeout-fixture");
                super::process::command(
                    Command::new("rustc")
                        .args([
                            "--test",
                            "--edition=2024",
                            "tests/fixtures/stalled-test.rs",
                            "-o",
                        ])
                        .arg(&fixture),
                    &workspace.join("timeout-build.log"),
                    Duration::from_mins(1),
                    &control,
                )?;
                report["gates"][index]["executed_fixture"] = json!("unbounded_test_fixture");
                report["gates"][index]["fixture_sha256"] =
                    json!(super::snapshot::digest(&fixture)?);
                super::process::command(
                    Command::new(&fixture).args([
                        "unbounded_test_fixture",
                        "--exact",
                        "--nocapture",
                    ]),
                    &log,
                    Duration::from_millis(150),
                    &control,
                )
            } else if gate.group == "cgroup" {
                let input = json!({"binary":binary,"name":gate.name,"environment":env,"workspace":workspace});
                let input_path = workspace.join("delegated.json");
                common::save(&input_path, &input)?;
                super::process::command(
                    Command::new("systemd-run")
                        .args([
                            "--user",
                            "--scope",
                            "--collect",
                            "--quiet",
                            "--expand-environment=no",
                            "--property=Delegate=yes",
                        ])
                        .arg(std::env::current_exe()?)
                        .arg("--delegated")
                        .arg(input_path),
                    &log,
                    GATE_TIMEOUT,
                    &control,
                )
            } else {
                super::process::command(
                    Command::new(binary)
                        .args([
                            &gate.name,
                            "--exact",
                            "--ignored",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .envs(&env)
                        .current_dir(&workspace),
                    &log,
                    GATE_TIMEOUT,
                    &control,
                )
            };
            report["gates"][index]["wall_seconds"] = json!(started.elapsed().as_secs_f64());
            report["gates"][index]["product_resources"] = super::measure::finish(&evidence, index)?;
            let verified = result.and_then(|output| {
                common::require_one_passed(&output)?;
                verify_candidates(&evidence, &pinned)?;
                verify_artifacts(&artifacts, &report["artifact_pins"])?;
                Ok(())
            });
            // Preserve native filesystem diagnostics before destroying the VM.
            // tar keeps symlinks and ignores live sockets without following them.
            let archive = format!("g{index}.tar");
            let archived = super::process::command(
                Command::new("tar")
                    .args(["--one-file-system", "-cf"])
                    .arg(evidence.join(&archive))
                    .args(["-C", "/work", "--"])
                    .arg(format!("g{index}")),
                &evidence.join(format!("archive-{index}.log")),
                Duration::from_mins(2),
                &control,
            )
            .map(|_| ());
            report["gates"][index]["workspace_archive"] = json!(archive);
            if let Err(error) = &archived {
                report["gates"][index]["workspace_archive_error"] = json!(error.to_string());
            }
            let verified = verified.and(archived);
            report["gates"][index]["status"] = json!(if verified.is_ok() {
                "passed"
            } else {
                "failed"
            });
            if let Err(error) = &verified {
                report["gates"][index]["error"] = json!(error.to_string());
            }
            super::evidence::save(&evidence.join("guest-report.json"), &report)?;
            if verified.is_err() {
                failures += 1;
            }
            super::process::command(
                Command::new("chmod")
                    .args(["-R", "u+w"])
                    .arg(&workspace),
                &evidence.join(format!("cleanup-{index}.log")),
                Duration::from_mins(1),
                &control,
            )?;
            fs::remove_dir_all(&workspace)?;
        }
        if failures != 0 {
            return Err(
                format!("{failures} selected VM gates failed; all results preserved").into(),
            );
        }
        if ecosystem {
            report["ecosystem"] = super::ecosystem::guest(&evidence, &control)?;
            verify_candidates(&evidence, &pinned)?;
            verify_artifacts(&artifacts, &report["artifact_pins"])?;
        }
        super::snapshot::verify_files(Path::new("/work/src"), &source_pins)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })();
    report["status"] = json!(if outcome.is_ok() {
        "passed"
    } else {
        "failed"
    });
    if let Err(error) = &outcome {
        report["error"] = json!(error.to_string());
    }
    super::evidence::save(&evidence.join("guest-report.json"), &report)?;
    outcome
}

fn qualify(evidence: &Path, control: &Control) -> Result<()> {
    super::process::command(
        Command::new("bash").args(["-euxo", "pipefail", "-c", QUALIFY]),
        &evidence.join("qualification.log"),
        Duration::from_mins(1),
        control,
    )?;
    super::process::command(
        &mut Command::new(evidence.join("prepared-payloads/capabilities")),
        &evidence.join("capabilities.log"),
        Duration::from_secs(15),
        control,
    )?;
    Ok(())
}

const QUALIFY: &str = include_str!("qualify.sh");

fn audit_registry(
    artifacts: &BTreeMap<String, PathBuf>,
    evidence: &Path,
    control: &Control,
) -> Result<()> {
    for target in artifacts
        .keys()
        .filter(|key| key.contains('/') && !key.ends_with("/vm_guest"))
    {
        let binary = artifacts
            .get(target)
            .ok_or("missing registry target")?;
        let listing = super::process::command(
            Command::new(binary).args(["--list", "--ignored"]),
            &evidence.join(format!("list-{}.log", target.replace('/', "-"))),
            Duration::from_secs(20),
            control,
        )?;
        let actual: BTreeSet<_> = listing
            .lines()
            .filter_map(|line| line.strip_suffix(": test"))
            .map(str::to_owned)
            .collect();
        let expected: BTreeSet<_> = common::gates()
            .into_iter()
            .filter(|gate| format!("{}/{}", gate.package, gate.target) == *target)
            .map(|gate| gate.name)
            .collect();
        if actual != expected {
            return Err(format!(
                "ignored test inventory changed in {target}; missing={:?}, unclassified={:?}",
                expected.difference(&actual).collect::<Vec<_>>(),
                actual.difference(&expected).collect::<Vec<_>>()
            )
            .into());
        }
    }
    Ok(())
}

fn prepare_candidates(
    artifacts: &BTreeMap<String, PathBuf>,
    evidence: &Path,
    control: &Control,
) -> Result<BTreeMap<String, String>> {
    let candidates = evidence.join("candidates");
    common::private(&candidates)?;
    let mut pins = BTreeMap::new();
    for name in ["srx", "syrox-worker"] {
        let source = artifacts
            .get(name)
            .ok_or("candidate binary missing")?;
        pins.insert(
            name.to_owned(),
            super::snapshot::copy_candidate(source, &candidates.join(name), 128 * 1024 * 1024)?,
        );
    }
    for name in ["session-payload", "path-payload"] {
        let source = Path::new("tests/fixtures").join(format!("{name}.c"));
        if !source.is_file() {
            return Err(format!("required fixture missing: {}", source.display()).into());
        }
        super::snapshot::copy_candidate(
            &evidence.join("prepared-payloads").join(name),
            &candidates.join(name),
            128 * 1024 * 1024,
        )?;
        pins.insert(
            name.to_owned(),
            super::snapshot::digest(&candidates.join(name))?,
        );
    }
    // Check executable structure via binutils in the pinned guest image.
    for name in pins.keys() {
        let binary = candidates.join(name);
        let headers = super::process::command(
            Command::new("readelf").arg("-l").arg(&binary),
            &evidence.join(format!("{name}-elf.log")),
            Duration::from_secs(15),
            control,
        )?;
        let dynamic = super::process::command(
            Command::new("readelf").arg("-d").arg(&binary),
            &evidence.join(format!("{name}-dynamic.log")),
            Duration::from_secs(15),
            control,
        )?;
        if headers
            .lines()
            .any(|line| line.trim_start().starts_with("INTERP"))
            || dynamic.contains("(NEEDED)")
        {
            return Err(format!("candidate is not static: {name}").into());
        }
        fs::set_permissions(binary, fs::Permissions::from_mode(0o500))?;
    }
    let native = Path::new(common::GUEST_CANDIDATES);
    common::private(native)?;
    for name in pins.keys() {
        let binary = native.join(name);
        super::snapshot::copy_candidate(&candidates.join(name), &binary, 128 * 1024 * 1024)?;
        fs::set_permissions(binary, fs::Permissions::from_mode(0o500))?;
    }
    verify_candidates(evidence, &pins)?;
    let help = super::process::command(
        Command::new(native.join("srx")).arg("--help"),
        &evidence.join("candidate-help.log"),
        Duration::from_secs(15),
        control,
    )?;
    if !help.contains("Usage:") {
        return Err("candidate help fixture failed".into());
    }
    let artifact_pins: BTreeMap<_, _> = artifacts
        .values()
        .map(|path| {
            Ok((
                path.to_string_lossy().into_owned(),
                super::snapshot::digest(path)?,
            ))
        })
        .collect::<Result<_>>()?;
    common::save(
        &evidence.join("artifact-pins.json"),
        &artifact_pins,
    )?;
    verify_source_identity(artifacts, evidence)?;
    common::save(&candidates.join("pins.json"), &pins)?;
    Ok(pins)
}

fn verify_source_identity(artifacts: &BTreeMap<String, PathBuf>, evidence: &Path) -> Result<()> {
    let cache_pin = cache_identity(evidence)?;
    if cache_pin.is_file() {
        let expected: BTreeMap<String, String> = serde_json::from_slice(&fs::read(&cache_pin)?)?;
        let actual: BTreeMap<String, String> = artifacts
            .iter()
            .map(|(name, path)| Ok((name.clone(), super::snapshot::digest(path)?)))
            .collect::<Result<_>>()?;
        if expected != actual {
            return Err(
                "cached candidate/libtest identity changed for the same sources and environment"
                    .into(),
            );
        }
    } else {
        common::private(
            cache_pin
                .parent()
                .ok_or("cache identity parent")?,
        )?;
        let stable_pins: BTreeMap<String, String> = artifacts
            .iter()
            .map(|(name, path)| Ok((name.clone(), super::snapshot::digest(path)?)))
            .collect::<Result<_>>()?;
        common::save(&cache_pin, &stable_pins)?;
    }
    Ok(())
}

fn cache_identity(evidence: &Path) -> Result<PathBuf> {
    let key = fs::read_to_string(evidence.join("cache-key"))?;
    if !super::snapshot::valid_digest(&key) {
        return Err("invalid source/environment cache key".into());
    }
    Ok(Path::new("/cache/identities").join(format!("{key}.json")))
}

fn verify_artifacts(_artifacts: &BTreeMap<String, PathBuf>, pins: &Value) -> Result<()> {
    let pins: BTreeMap<String, String> = serde_json::from_value(pins.clone())?;
    for (path, expected) in pins {
        if super::snapshot::digest(Path::new(&path))? != expected {
            return Err(format!("candidate or libtest bytes changed: {path}").into());
        }
    }
    Ok(())
}

fn verify_candidates(evidence: &Path, pins: &BTreeMap<String, String>) -> Result<()> {
    super::snapshot::verify_files(Path::new(common::GUEST_CANDIDATES), pins)?;
    super::snapshot::verify_files(&evidence.join("candidates"), pins)
}

fn environment(
    _evidence: &Path,
    workspace: &Path,
    pins: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    let candidates = Path::new(common::GUEST_CANDIDATES);
    for (role, name) in [
        ("OWNER_WORKER", "syrox-worker"),
        ("SESSION_PAYLOAD", "session-payload"),
        ("PATH_PAYLOAD", "path-payload"),
        ("MANAGED_WORKER", "syrox-worker"),
        ("RESTART_WORKER", "syrox-worker"),
        ("RESTART_PAYLOAD", "session-payload"),
        ("INTERACTIVE_CLI", "srx"),
        ("INTERACTIVE_WORKER", "syrox-worker"),
        ("INTERACTIVE_PAYLOAD", "session-payload"),
    ] {
        env.insert(
            format!("SYROX_{role}"),
            candidates
                .join(name)
                .to_string_lossy()
                .into_owned(),
        );
        env.insert(
            format!("SYROX_{role}_SHA256"),
            pins.get(name)
                .ok_or("fixture pin missing")?
                .clone(),
        );
    }
    for role in [
        "SESSION_STATE_PARENT",
        "SESSION_SECRET_PARENT",
        "MANAGED_SOCKET_PARENT",
        "RESTART_PARENT",
        "INTERACTIVE_PARENT",
    ] {
        let directory = workspace.join(role.to_ascii_lowercase());
        common::private(&directory)?;
        env.insert(
            format!("SYROX_{role}"),
            directory.to_string_lossy().into_owned(),
        );
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR")?;
    env.insert(
        "SYROX_SYSTEMD_USER_BUS".into(),
        format!("{runtime}/bus"),
    );
    env.insert(
        "SYROX_INTERACTIVE_BUS".into(),
        format!("{runtime}/bus"),
    );
    env.insert(
        "TMPDIR".into(),
        workspace.to_string_lossy().into_owned(),
    );
    env.insert(
        "SYROX_RESTART_UNITS".into(),
        format!("{}/.config/systemd/user", std::env::var("HOME")?),
    );
    let unit = "syrox-persistent-gate-vm.service";
    let units = PathBuf::from(std::env::var("HOME")?).join(".config/systemd/user");
    fs::create_dir_all(&units)?;
    fs::write(
        units.join(unit),
        "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n",
    )?;
    env.insert(
        "SYROX_SYSTEMD_PERSISTENT_UNIT".into(),
        unit.into(),
    );
    Ok(env)
}

fn delegated(input: &Value) -> Result<()> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let parent = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("cgroup v2 membership missing")?;
    if parent == "/" || parent.split('/').any(|part| part == "..") {
        return Err("nonroot delegated subtree required".into());
    }
    let parent = format!("/sys/fs/cgroup{parent}");
    let mut env: BTreeMap<String, String> = serde_json::from_value(input["environment"].clone())?;
    env.insert(
        "SYROX_CGROUP_RETIREMENT_PARENT".into(),
        parent.clone(),
    );
    env.insert("SYROX_TEST_CGROUP_DELEGATE".into(), parent);
    env.insert(
        "SYROX_TEST_CGROUP_SLEEP".into(),
        "/usr/bin/sleep".into(),
    );
    let status = Command::new(
        input["binary"]
            .as_str()
            .ok_or("delegated binary missing")?,
    )
    .args([
        input["name"]
            .as_str()
            .ok_or("delegated exact gate missing")?,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .envs(env)
    .current_dir(
        input["workspace"]
            .as_str()
            .ok_or("delegated workspace missing")?,
    )
    .status()?;
    if !status.success() {
        return Err(format!("delegated test failed: {status}").into());
    }
    Ok(())
}

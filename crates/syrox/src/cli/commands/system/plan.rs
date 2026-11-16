//! Read-only declaration comparison; observations are not apply authorizations.

use std::{
    fs::File,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};
use syrox_engine::{
    cancellation::Cancellation,
    plan::{PlanKernel, PlanSysctl},
    project::{
        CheckConfiguration, plan_project_consumer_with,
        reference::{ProjectReference, parse_project_reference},
    },
    store::ContentDigest,
    system::{filesystem::Observation, inventory, sysctl},
};

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Explicit locked project and output, for example .#host.
    reference: String,
    #[arg(long)]
    json: bool,
    /// Also admit the System budget against this explicit local build.system policy.
    #[arg(long, value_name = "PATH")]
    builder_config: Option<PathBuf>,
}

pub(super) fn run(
    arguments: &Arguments,
    checks: &CheckConfiguration,
    cancellation: &Cancellation,
) -> Result<ExitCode, String> {
    let ProjectReference::Project {
        path,
        export: Some(output),
    } = parse_project_reference(&arguments.reference).map_err(|error| error.to_string())?
    else {
        return Err("system plan requires an explicit locked System or HostConfiguration output, for example .#host".into());
    };
    cancellation
        .check()
        .map_err(|error| error.to_string())?;
    let mut checks = checks.clone();
    checks.github.cancellation = cancellation.clone();
    let plan = plan_project_consumer_with(path, &checks, output)
        .map_err(|error| crate::cli::presentation::project_error(&error))?;
    let system = plan
        .systems()
        .find(|system| system.name == output);
    let host = plan
        .host_configurations()
        .find(|host| host.name == output);
    let (kind, kernel, settings, storage, mut pending) = match (system, host) {
        (Some(system), None) => (
            "System", Some(&system.kernel), system.kernel.sysctls.as_slice(), Some(&system.storage),
            vec!["builder admission and artifacts", "kernel/module/configuration compatibility",
                "boot and generation state", "storage metadata and exclusive device use",
                "persistent data compatibility", "service health and authority"],
        ),
        (None, Some(host)) => {
            let mut pending = vec!["adoption and resource ownership"];
            if !host.modules.is_empty() || host.kernel.as_ref().is_some_and(|k| !k.load.is_empty()) {
                pending.push("module state and parameters");
            }
            if !host.mounts.is_empty() { pending.push("mount filesystem identities"); }
            if !host.services.services().is_empty() || !host.services.pkgs().is_empty() {
                pending.push("service state and authority");
            }
            if host.kernel.is_some() { pending.push("kernel artifacts and boot confirmation"); }
            ("HostConfiguration", host.kernel.as_ref(), host.sysctls.as_slice(), None, pending)
        },
        _ => return Err("system plan selects only System or HostConfiguration; use services commands for Services".into()),
    };
    let builder = arguments.builder_config.as_deref().map(|path| {
        let system = system.ok_or("--builder-config requires a System output; HostConfiguration has no full-system build budget")?;
        builder_admission(path, system.budget)
    }).transpose()?;
    if builder.is_some() {
        pending[0] = "builder capacity, enforcement and artifacts";
    }
    let namespaces = Namespaces::pin()?;
    let observed = inventory::inspect_with_cancellation(|| cancellation.is_cancelled())
        .map_err(|error| error.to_string())?;
    let inventory_sha256 = observed
        .fingerprint()
        .map_err(|error| error.to_string())?;
    let mut settings = settings.iter().collect::<Vec<_>>();
    if let (Some(_host), Some(kernel)) = (host, kernel) {
        settings.extend(kernel.sysctls.iter());
    }
    settings.sort_by(|left, right| left.name.cmp(&right.name));
    if !settings.is_empty() {
        pending.push("sysctl application and restoration contracts");
    }
    let sysctls = settings
        .into_iter()
        .map(|setting| compare_sysctl(setting, cancellation))
        .collect::<Result<Vec<_>, _>>()?;
    let storage = storage.map(|layout| match layout.plan(&observed) {
        Ok(binding) => serde_json::json!({"status": "bound_to_inventory", "binding": binding,
            "effect_if_provisioned": "destructive", "metadata_verified": false,
            "exclusive_use_verified": false}),
        Err(error) => serde_json::json!({"status": "unresolved", "reason": error.to_string(),
            "effect_if_provisioned": "destructive"}),
    });
    cancellation
        .check()
        .map_err(|error| error.to_string())?;
    let namespace_ids = namespaces.revalidate()?;
    let declaration = plan.to_string();
    let mut report = serde_json::json!({
        "version": 1, "kind": "system_observation_plan", "target": "current_process_namespaces",
        "selected_output": output, "declaration_kind": kind,
        "namespace_ids": namespace_ids,
        "declaration": declaration, "declaration_sha256": ContentDigest::sha256(declaration.as_bytes()).to_string(),
        "inventory": observed, "inventory_sha256": inventory_sha256,
        "sysctls": sysctls, "storage": storage, "kernel": kernel_report(kernel, &observed.kernel_release),
        "pending_verification": pending, "can_apply": false,
        "ownership_established": false, "observation_is_atomic": false,
    });
    let mut canonical = if let Some(builder) = builder {
        report["version"] = serde_json::json!(2);
        report["builder_admission"] = builder;
        b"srx-system-observation-plan-v2\n".to_vec()
    } else {
        b"srx-system-observation-plan-v1\n".to_vec()
    };
    canonical.extend(serde_json::to_vec(&report).map_err(|error| error.to_string())?);
    let digest = ContentDigest::sha256(&canonical).to_string();
    if arguments.json {
        println!(
            "{}",
            serde_json::json!({"observation_sha256": digest, "plan": report})
        );
    } else {
        print!("{declaration}");
        println!("system observation sha256 {digest}");
        println!("target current process namespaces; declaration {kind} {output:?}");
        for setting in report["sysctls"]
            .as_array()
            .expect("constructed array")
        {
            println!(
                "sysctl {} desired {} observed {} comparison {}",
                setting["name"], setting["desired"], setting["observed"], setting["comparison"]
            );
        }
        if let Some(storage) = storage {
            println!("storage {storage}");
        }
        if !report["kernel"].is_null() {
            println!("kernel {}", report["kernel"]);
        }
        if let Some(builder) = report.get("builder_admission") {
            println!("builder policy admission {builder}");
        }
        println!(
            "pending verification {}",
            report["pending_verification"]
        );
        println!("apply unavailable; resource ownership and parameter restoration are unverified");
    }
    Ok(ExitCode::SUCCESS)
}

fn builder_admission(
    path: &Path,
    request: syrox_engine::system::budget::BuildBudget,
) -> Result<serde_json::Value, String> {
    use std::fmt::Write as _;
    use syrox_engine::{config::UserConfiguration, systemd::SystemdScope};
    let configuration = UserConfiguration::load(Some(path)).map_err(|e| e.to_string())?;
    let builder = configuration
        .system_build()
        .ok_or("builder configuration must explicitly set build.system and all maximum limits")?;
    let admitted = builder
        .admit(request)
        .map_err(|e| e.to_string())?;
    let worker = builder.worker();
    let scope = match worker.scope() {
        SystemdScope::System => serde_json::json!({"kind": "system"}),
        SystemdScope::User {
            bus_socket,
        } => serde_json::json!({"kind": "user", "user_bus": bus_socket}),
    };
    let mut fingerprint = String::with_capacity(64);
    for byte in admitted.policy_fingerprint() {
        write!(fingerprint, "{byte:02x}").expect("String write");
    }
    Ok(serde_json::json!({
        "policy_scope": "explicit_local_builder_configuration", "policy_admitted": true,
        "request": admitted.request(), "maximum": builder.limits().maximum(), "policy_sha256": fingerprint,
        "worker": worker.worker(), "worker_sha256": worker.worker_digest().to_string(),
        "scope": scope, "socket_parent": worker.socket_parent(), "helper_socket": builder.helper_socket(),
        "worker_verified": false, "manager_verified": false, "helper_authority_verified": false,
        "capacity_verified": false, "runtime_enforcement_verified": false,
    }))
}

fn compare_sysctl(
    setting: &PlanSysctl,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, String> {
    let observed = sysctl::observe(&setting.name, || {
        cancellation
            .check()
            .map_err(std::io::Error::other)
    })
    .map_err(|error| error.to_string())?;
    let comparison = match &observed {
        Observation::Available {
            value,
        } if value == &setting.value => "equal",
        Observation::Available {
            ..
        } => "different",
        Observation::Unavailable {
            ..
        } => "unavailable",
    };
    Ok(
        serde_json::json!({"name": setting.name, "desired": setting.value, "observed": observed,
        "comparison": comparison, "application_contract_verified": false, "restoration_verified": false}),
    )
}

fn kernel_report(kernel: Option<&PlanKernel>, observed_release: &str) -> Option<serde_json::Value> {
    kernel.map(|kernel| serde_json::json!({"desired_release": kernel.release,
        "observed_release": observed_release, "release_text_matches": kernel.release == observed_release,
        "generation_change_requires_boot": true, "artifact_compatibility_verified": false,
        "boot_selection_verified": false}))
}

struct Namespaces(Vec<(&'static str, File)>);

impl Namespaces {
    fn pin() -> Result<Self, String> {
        [
            "user", "mnt", "net", "ipc", "uts", "pid", "cgroup",
        ]
        .into_iter()
        .map(|name| {
            File::open(format!("/proc/self/ns/{name}"))
                .map(|file| (name, file))
                .map_err(|error| format!("cannot pin current {name} namespace: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Self)
    }

    fn revalidate(&self) -> Result<serde_json::Value, String> {
        let mut identities = serde_json::Map::new();
        for (name, file) in &self.0 {
            let before = file
                .metadata()
                .map_err(|error| error.to_string())?;
            let after = std::fs::metadata(format!("/proc/self/ns/{name}"))
                .map_err(|error| error.to_string())?;
            if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
                return Err(format!(
                    "current {name} namespace changed during observation"
                ));
            }
            identities.insert(
                (*name).into(),
                serde_json::json!({"device": before.dev(), "inode": before.ino()}),
            );
        }
        Ok(serde_json::Value::Object(identities))
    }
}

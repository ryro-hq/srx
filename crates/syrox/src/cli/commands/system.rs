use std::{
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};
use syrox_engine::system::inventory::{self, SystemInventory};
use syrox_engine::{
    cancellation::Cancellation,
    system::filesystem::{self, Observation},
};

mod plan;

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Compare a locked `System` or `HostConfiguration` with current Linux observations.
    Plan(plan::Arguments),
    /// Read kernel, firmware, block-device and mount-namespace observations.
    Inspect {
        #[arg(long)]
        json: bool,
        /// Also observe capacity and project quotas of this existing directory.
        #[arg(long, value_name = "PATH")]
        builder_directory: Option<PathBuf>,
    },
    /// Inspect private build-storage recovery; reconcile only an explicitly reviewed hash.
    Recover {
        #[arg(long, value_name = "ID", value_parser = hex_value::<32>, required_unless_present = "workspace_operation", conflicts_with = "workspace_operation")]
        scratch_operation: Option<String>,
        #[arg(long, value_name = "ID", value_parser = hex_value::<32>, required_unless_present = "scratch_operation", conflicts_with = "scratch_operation")]
        workspace_operation: Option<String>,
        #[arg(long, value_name = "PATH")]
        helper_socket: PathBuf,
        /// Authorize reconciliation of this exact observed plan; retains the images.
        #[arg(long, value_name = "SHA256", value_parser = hex_value::<64>)]
        apply_plan: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(
    command: &Command,
    checks: &syrox_engine::project::CheckConfiguration,
) -> ExitCode {
    let signals = match crate::signals::OperationSignals::install() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = match command {
        Command::Plan(arguments) => plan::run(arguments, checks, &signals.cancellation),
        Command::Inspect {
            json,
            builder_directory,
        } => inspect(
            *json,
            builder_directory.as_deref(),
            &signals.cancellation,
        ),
        Command::Recover {
            scratch_operation,
            workspace_operation,
            helper_socket,
            apply_plan,
            json,
        } => match (
            scratch_operation.as_deref(),
            workspace_operation.as_deref(),
        ) {
            (Some(id), None) => recover(
                id,
                helper_socket,
                apply_plan.as_deref(),
                *json,
                false,
                &signals.cancellation,
            ),
            (None, Some(id)) => recover(
                id,
                helper_socket,
                apply_plan.as_deref(),
                *json,
                true,
                &signals.cancellation,
            ),
            _ => Err("select exactly one scratch or workspace operation".into()),
        },
    };
    crate::cli::presentation::render_cancellable_result(&signals, result)
}

fn recover(
    id: &str,
    endpoint: &Path,
    authorization: Option<&str>,
    json: bool,
    workspace: bool,
    cancellation: &Cancellation,
) -> Result<ExitCode, String> {
    use std::time::{Duration, Instant};
    use syrox_engine::system::helper_client::HelperClient;
    let deadline = Instant::now() + Duration::from_secs(30);
    let check = || {
        cancellation
            .check()
            .map_err(std::io::Error::other)
    };
    let client =
        HelperClient::connect(endpoint, check, deadline).map_err(|error| error.to_string())?;
    let value = if let Some(hash) = authorization {
        let result = if workspace {
            client.recover_workspace(id, hash, check, deadline)
        } else {
            client.recover(id, hash, check, deadline)
        };
        result.map_err(|error| error.to_string())?
    } else {
        let report = if workspace {
            client.inspect_workspace(id, check, deadline)
        } else {
            client.inspect(id, check, deadline)
        }
        .map_err(|error| error.to_string())?;
        serde_json::json!({ "version": 1, "plan": report.plan, "plan_sha256": report.plan_sha256 })
    };
    let output = if json {
        serde_json::to_string(&value)
    } else {
        serde_json::to_string_pretty(&value)
    }
    .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(ExitCode::SUCCESS)
}

fn hex_value<const LENGTH: usize>(value: &str) -> Result<String, String> {
    if value.len() == LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "expected {LENGTH} lowercase hexadecimal digits"
        ))
    }
}

// Caller-supplied paths must remain escaped in terminal diagnostics.
#[allow(clippy::unnecessary_debug_formatting)]
fn inspect(
    json: bool,
    builder_directory: Option<&Path>,
    cancellation: &Cancellation,
) -> Result<ExitCode, String> {
    let report = inventory::inspect_with_cancellation(|| cancellation.is_cancelled())
        .map_err(|error| error.to_string())?;
    let digest = report
        .fingerprint()
        .map_err(|error| error.to_string())?;
    let builder = builder_directory
        .map(|path| -> Result<_, String> {
            cancellation
                .check()
                .map_err(|error| error.to_string())?;
            if path.to_str().is_none() {
                return Err("builder directory path must be UTF-8 for observation output".into());
            }
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
                .open(path)
                .map_err(|error| format!("builder directory {path:?}: {error}"))?;
            let observation = filesystem::observe(&directory).map_err(|error| error.to_string())?;
            let external_uuid = match filesystem::external_uuid(&directory) {
                Ok(value) => Observation::Available {
                    value,
                },
                Err(error) => Observation::Unavailable {
                    errno: error.raw_os_error(),
                    reason: error.to_string(),
                },
            };
            let fingerprint = observation
                .fingerprint()
                .map_err(|error| error.to_string())?;
            cancellation
                .check()
                .map_err(|error| error.to_string())?;
            Ok((path, observation, fingerprint, external_uuid))
        })
        .transpose()?;
    if json {
        let mut value = serde_json::json!({"observation": "linux-kernel-interfaces", "digest": digest, "inventory": report});
        if let Some((path, observation, fingerprint, external_uuid)) = builder {
            value["builder_filesystem"] = serde_json::json!({"path":path, "digest":fingerprint, "observation":observation, "external_uuid":external_uuid});
        }
        println!("{value}");
    } else {
        print(&report, &digest);
        if let Some((path, observation, fingerprint, external_uuid)) = builder {
            println!("builder directory {path:?} sha256 {fingerprint}");
            match external_uuid {
                Observation::Available {
                    value,
                } => println!("  external filesystem UUID bytes={value}"),
                Observation::Unavailable {
                    reason,
                    ..
                } => println!("  external filesystem UUID unavailable: {reason}"),
            }
            println!(
                "  filesystem=0x{:x} device={} inode={} available_bytes={} available_inodes={}",
                observation.filesystem_type,
                observation.device,
                observation.inode,
                observation.available_bytes,
                observation.available_inodes
            );
            match observation.project {
                Observation::Unavailable {
                    reason,
                    ..
                } => println!("  project quotas unavailable: {reason}"),
                Observation::Available {
                    value: project,
                } => {
                    println!(
                        "  project={} children_inherit_project={}",
                        project.id, project.children_inherit_project
                    );
                    match project.state {
                        Observation::Available {
                            value: state,
                        } => println!(
                            "  accounting={} enforcement={}",
                            state.accounting, state.enforcement
                        ),
                        Observation::Unavailable {
                            reason,
                            ..
                        } => println!("  quota state unavailable: {reason}"),
                    }
                    match project.limits {
                        Observation::Available {
                            value: limits,
                        } => println!(
                            "  hard_bytes={} used_bytes={} hard_inodes={} used_inodes={}",
                            limit(limits.hard_bytes),
                            limits.used_bytes,
                            limit(limits.hard_inodes),
                            limits.used_inodes
                        ),
                        Observation::Unavailable {
                            reason,
                            ..
                        } => println!("  quota limits unavailable: {reason}"),
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn limit(value: Option<u64>) -> String {
    value.map_or_else(|| "unlimited".into(), |value| value.to_string())
}

fn print(report: &SystemInventory, digest: &str) {
    println!(
        "system inventory v{} sha256 {digest}",
        report.version
    );
    println!(
        "kernel {}; inspector {}; boot {}",
        report.kernel_release, report.inspector_architecture, report.boot_id
    );
    println!(
        "UEFI present: {}; KVM device present: {}",
        report.uefi_present, report.kvm_device_present
    );
    println!("block devices: {}", report.devices.len());
    for device in &report.devices {
        println!(
            "device {} {} bytes={} read_only={} node_matches={} path={}",
            device.name,
            device.number,
            device.capacity_bytes,
            device.read_only,
            device.device_node_matches,
            device.diagnostic_path.display()
        );
        println!(
            "  identity wwid={:?} serial={:?} dm_uuid={:?} partition_uuid={:?} diskseq={:?}",
            device.identity.wwid,
            device.identity.serial,
            device.identity.device_mapper_uuid,
            device.identity.partition_uuid,
            device.identity.disk_sequence
        );
        if let Some(partition) = &device.partition {
            println!(
                "  partition {} parent={} start_bytes={}",
                partition.number, partition.parent, partition.start_bytes
            );
        }
        println!(
            "  blocks logical={} physical={}; holders={:?}; slaves={:?}",
            device.logical_block_bytes, device.physical_block_bytes, device.holders, device.slaves
        );
    }
    println!(
        "mounts: {} in current namespace",
        report.mounts.len()
    );
    for mount in &report.mounts {
        println!(
            "mount {} {} {:?} filesystem={} read_only={}",
            mount.id, mount.device, mount.target, mount.filesystem, mount.read_only
        );
    }
}

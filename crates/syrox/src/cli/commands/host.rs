#[cfg(target_os = "linux")]
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use syrox_engine::{
    cancellation::Cancellation, platform::linux::host::HostCapabilityStatus,
    platform::linux::host::inspect_host_with_probe, systemd::SystemdManager, systemd::SystemdScope,
};

#[derive(Debug, clap::Args)]
pub(crate) struct Arguments {
    /// Inspect a selected cgroup parent beneath /sys/fs/cgroup; defaults to this process's membership.
    #[arg(long)]
    cgroup_parent: Option<PathBuf>,
    /// Probe resource limits and migration with a temporary cgroup and a gated srx child.
    #[arg(long)]
    probe_cgroup: bool,
    /// Inspect the user manager through this explicit absolute bus socket.
    #[arg(long, conflicts_with = "systemd_system", value_parser = absolute_bus)]
    systemd_user_bus: Option<PathBuf>,
    /// Inspect the system manager through its local system bus.
    #[arg(long)]
    systemd_system: bool,
    /// Compare the actual interfaces with the canonical supervision or managed profile.
    #[arg(long, default_value = "managed", value_parser = ["supervision", "managed"])]
    systemd_profile: String,
    /// An already loaded service; inspection never loads or starts it.
    #[arg(long, default_value = "dbus.service")]
    systemd_unit: String,
}

fn absolute_bus(text: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("systemd user bus must be an absolute path without parent traversal".into());
    }
    Ok(path)
}

fn manager_scope(args: &Arguments) -> Option<SystemdScope> {
    args.systemd_user_bus
        .as_ref()
        .map(|bus_socket| SystemdScope::User {
            bus_socket: bus_socket.clone(),
        })
        .or_else(|| {
            args.systemd_system
                .then_some(SystemdScope::System)
        })
}

fn inspect_manager(scope: SystemdScope, args: &Arguments) -> ExitCode {
    match &scope {
        SystemdScope::User {
            bus_socket,
        } => {
            println!("systemd scope user; bus {}", bus_socket.display());
        }
        SystemdScope::System => println!("systemd scope system; bus /run/dbus/system_bus_socket"),
    }
    let cancellation = Cancellation::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = SystemdManager::connect(
        scope,
        deadline.saturating_duration_since(Instant::now()),
        &cancellation,
    )
    .and_then(|mut manager| {
        manager.inspect_interfaces(
            &args.systemd_profile,
            &syrox_engine::systemd::SystemdUnitName::new(args.systemd_unit.clone())?,
            deadline.saturating_duration_since(Instant::now()),
            &cancellation,
        )
    });
    println!(
        "systemd execution permissions, FDSTORE, journald, logout and boot: not verified; require operation-specific probes"
    );
    match result {
        Ok(report) => {
            match serde_json::to_string_pretty(&report) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
            if report.missing.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            println!("systemd API: unavailable ({error})");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn probe_child() -> ExitCode {
    // The parent waits for this byte before writing cgroup.procs; this process
    // cannot run a recipe and remains alive until its stdin is closed.
    let result = (|| -> std::io::Result<()> {
        std::io::stdout().write_all(b"R")?;
        std::io::stdout().flush()?;
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte)
    })();
    if result.is_err() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub(crate) fn inspect(args: &Arguments) -> ExitCode {
    let outcome = match inspect_host_with_probe(args.cgroup_parent.as_deref(), args.probe_cgroup) {
        Ok(report) => {
            println!("cgroup parent {}", report.cgroup_parent.display());
            for item in report.capabilities {
                match item.status {
                    HostCapabilityStatus::Available(detail) => {
                        println!("{}: available ({detail})", item.name);
                    }
                    HostCapabilityStatus::Unavailable(detail) => {
                        println!("{}: unavailable ({detail})", item.name);
                    }
                    HostCapabilityStatus::NeedsActiveProbe(detail) => {
                        println!("{}: requires active probe ({detail})", item.name);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    };
    if let Some(scope) = manager_scope(args) {
        let result = inspect_manager(scope, args);
        if result != ExitCode::SUCCESS {
            return result;
        }
    }
    outcome
}

/// The engine owns this contract; catalogs never maintain a second copy.
#[cfg(target_os = "linux")]
pub(crate) fn contract() -> ExitCode {
    match syrox_engine::systemd::interface_contract().and_then(|contract| {
        Ok(serde_json::to_string_pretty(&contract).map_err(std::io::Error::other)?)
    }) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    fn parse(args: &[&str]) -> Result<Arguments, clap::Error> {
        let cli = crate::cli::arguments::Cli::try_parse_from(args)?;
        let crate::cli::arguments::Command::Host {
            command: crate::cli::arguments::HostCommand::Inspect(arguments),
        } = cli.command
        else {
            panic!("expected host inspect");
        };
        Ok(arguments)
    }

    #[test]
    fn manager_inspection_requires_explicit_scope_and_rejects_ambiguous_authority() {
        assert_eq!(
            manager_scope(&parse(&["srx", "host", "inspect"]).unwrap()),
            None
        );
        assert_eq!(
            manager_scope(
                &parse(&[
                    "srx",
                    "host",
                    "inspect",
                    "--systemd-system"
                ])
                .unwrap()
            ),
            Some(SystemdScope::System)
        );
        assert_eq!(
            manager_scope(
                &parse(&[
                    "srx",
                    "host",
                    "inspect",
                    "--systemd-user-bus",
                    "/run/user/1000/bus"
                ])
                .unwrap()
            ),
            Some(SystemdScope::User {
                bus_socket: "/run/user/1000/bus".into()
            })
        );
        for bus in ["relative/bus", "/run/../bus"] {
            assert!(
                parse(&[
                    "srx",
                    "host",
                    "inspect",
                    "--systemd-user-bus",
                    bus
                ])
                .is_err()
            );
        }
        assert!(
            parse(&[
                "srx",
                "host",
                "inspect",
                "--systemd-user-bus",
                "/run/user/1000/bus",
                "--systemd-system"
            ])
            .is_err()
        );
    }
}

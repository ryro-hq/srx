//! Explicit administrator-selected systemd activation for the scratch helper.
//!
//! Rendering is pure: it grants no authority, inspects no filesystem and installs
//! no unit. An administrator must prepare and verify the pinned executable,
//! policy and private state before installing the resulting system units.

use std::fmt::Write as _;
use std::io;
use std::path::{Component, Path, PathBuf};

pub const SOCKET_UNIT: &str = "syrox-system-helper.socket";
pub const SERVICE_UNIT: &str = "syrox-system-helper@.service";

/// The helper's per-connection overhead envelope, separate from build budgets.
/// The socket also bounds concurrent privileged instances. Recipes select none
/// of these values, and ordinary non-root build/service profiles are unchanged.
#[derive(Clone, Copy, Debug)]
pub struct HelperServiceLimits {
    pub memory_bytes: u64,
    pub cpu_percent: u32,
    pub processes: u32,
    pub descriptors: u32,
    pub duration_seconds: u32,
    pub connections: u32,
}

#[derive(Clone, Debug)]
pub struct HelperActivation {
    pub executable: PathBuf,
    pub policy: PathBuf,
    pub state_directory: PathBuf,
    pub socket: PathBuf,
    /// Socket inode stays root-owned; this group may connect. The helper still
    /// independently checks the exact configured `SO_PEERCRED` uid/gid.
    pub socket_group: u32,
    pub limits: HelperServiceLimits,
}

#[derive(Clone, Debug)]
pub struct ActivationUnits {
    pub socket: String,
    pub service: String,
}

impl HelperActivation {
    pub fn render(&self) -> io::Result<ActivationUnits> {
        let executable = quote(&self.executable)?;
        let policy = quote(&self.policy)?;
        let state = quote(&self.state_directory)?;
        let socket = text(&self.socket)?;
        // ListenSequentialPacket takes an address, not an ExecStart word list.
        // Restrict that address to a literal canonical pathname and sun_path's
        // actual byte bound; no specifier, abstract or network address is used.
        if socket.len() > 107
            || !socket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err(refused(
                "helper socket requires a literal Unix pathname of at most 107 bytes",
            ));
        }
        let limits = self.limits;
        if limits.memory_bytes == 0
            || limits.memory_bytes > i64::MAX as u64
            || limits.cpu_percent == 0
            || limits.processes == 0
            || limits.descriptors < 8
            || limits.duration_seconds == 0
            || !(1..=64).contains(&limits.connections)
        {
            return Err(refused(
                "helper activation requires finite positive service and connection limits",
            ));
        }
        let socket = format!(
            "# syrox-private-scratch-activation-v1\n[Unit]\nDescription=SRX private scratch activation\n\n[Socket]\nListenSequentialPacket={socket}\nAccept=yes\nSocketUser=0\nSocketGroup={}\nSocketMode=0660\nDirectoryMode=0755\nMaxConnections={}\nMaxConnectionsPerSource={}\nRemoveOnStop=yes\nFileDescriptorName=connection\n\n[Install]\nWantedBy=sockets.target\n",
            self.socket_group, limits.connections, limits.connections
        );
        let mut service = String::from(
            "# syrox-private-scratch-activation-v1\n[Unit]\nDescription=SRX private scratch connection\nCollectMode=inactive-or-failed\n\n[Service]\nType=exec\nUser=0\nGroup=0\nDynamicUser=no\nRestart=no\nKillMode=control-group\nSendSIGKILL=yes\nTimeoutStopSec=10s\nOOMPolicy=kill\nUMask=0077\nWorkingDirectory=/\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\nNoNewPrivileges=yes\nPrivateMounts=yes\nPrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nDevicePolicy=closed\nDeviceAllow=/dev/null rw\nDeviceAllow=/dev/loop-control rw\nDeviceAllow=block-loop rw\nCapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETPCAP CAP_SYS_ADMIN CAP_SYS_CHROOT\nRestrictAddressFamilies=AF_UNIX\n",
        );
        // ':' disables environment substitution; quote doubles '%' separately
        // because systemd expands specifiers even inside quoted command words.
        writeln!(service, "ExecStart=:{executable} \"--policy\" {policy}\nReadWritePaths={state}\nMemoryMax={}\nCPUQuota={}%\nTasksMax={}\nLimitNOFILE={}\nRuntimeMaxSec={}s",
            limits.memory_bytes, limits.cpu_percent, limits.processes, limits.descriptors, limits.duration_seconds)
            .expect("writing to a String cannot fail");
        Ok(ActivationUnits {
            socket,
            service,
        })
    }
}

fn text(path: &Path) -> io::Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| refused("helper activation paths require UTF-8"))?;
    if !path.is_absolute()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || value[1..]
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(refused(
            "helper activation paths require bounded canonical absolute names without controls",
        ));
    }
    Ok(value)
}

fn quote(path: &Path) -> io::Result<String> {
    let mut result = String::from("\"");
    for c in text(path)?.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '%' => result.push_str("%%"),
            _ => result.push(c),
        }
    }
    result.push('"');
    Ok(result)
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(root: &Path) -> HelperActivation {
        HelperActivation {
            executable: root.join("helper"),
            policy: root.join("policy.json"),
            state_directory: root.join("state"),
            socket: "/run/syrox/system-helper.sock".into(),
            socket_group: 1000,
            limits: HelperServiceLimits {
                memory_bytes: 536_870_912,
                cpu_percent: 100,
                processes: 8,
                descriptors: 128,
                duration_seconds: 600,
                connections: 4,
            },
        }
    }

    #[test]
    fn rendering_is_pure_and_preserves_literal_exec_words() {
        let temporary = tempfile::tempdir().unwrap();
        let absent = temporary
            .path()
            .join("absent %n $HOME \"quoted\"");
        let units = configuration(&absent).render().unwrap();
        assert!(!absent.exists());
        assert!(units.service.contains("ExecStart=:\""));
        assert!(units.service.contains("%%n $HOME \\\"quoted\\\""));
        assert!(
            units
                .socket
                .contains("Accept=yes\nSocketUser=0\nSocketGroup=1000\nSocketMode=0660")
        );
        assert!(units.service.contains(
            "MemoryMax=536870912\nCPUQuota=100%\nTasksMax=8\nLimitNOFILE=128\nRuntimeMaxSec=600s"
        ));
        assert!(units.service.contains("Restart=no"));
    }

    #[test]
    fn malformed_paths_addresses_and_unbounded_envelopes_are_rejected() {
        for bad in [
            "relative",
            "/state/../policy",
            "/state//policy",
            "/state/./policy",
            "/state\nExecStart=/bin/sh",
        ] {
            let mut config = configuration(Path::new("/explicit"));
            config.policy = bad.into();
            assert!(config.render().is_err());
        }
        for bad in [
            "@abstract",
            "/run/a%n.sock",
            "/run/with space.sock",
            "/run/a\n.sock",
            &format!("/{}", "a".repeat(107)),
        ] {
            let mut config = configuration(Path::new("/explicit"));
            config.socket = bad.into();
            assert!(config.render().is_err());
        }
        let mut config = configuration(Path::new("/explicit"));
        config.limits.memory_bytes = u64::MAX;
        assert!(config.render().is_err());
        config.limits.memory_bytes = 536_870_912;
        config.limits.connections = 0;
        assert!(config.render().is_err());
        config.limits.connections = 65;
        assert!(config.render().is_err());
    }
}

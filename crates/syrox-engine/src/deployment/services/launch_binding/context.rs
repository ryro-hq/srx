use super::{Result, invalid, path_text};
use crate::{store::ContentDigest, systemd::SystemdScope};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Manager {
    User {
        bus_socket: String,
    },
    System,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OsLaunchContext {
    manager: Manager,
    store: String,
    fragment: String,
    uid: u32,
    gid: u32,
    start_us: u64,
    stop_us: u64,
    restart: crate::execution::restart::ProcessRestart,
}
impl OsLaunchContext {
    pub(crate) fn new(
        scope: SystemdScope,
        store: PathBuf,
        fragment: PathBuf,
        uid: u32,
        gid: u32,
        start_timeout: Duration,
        stop_timeout: Duration,
    ) -> Result<Self> {
        let context = Self {
            manager: match scope {
                SystemdScope::User {
                    bus_socket,
                } => Manager::User {
                    bus_socket: path_text(&bus_socket)?.into(),
                },
                SystemdScope::System => Manager::System,
            },
            store: store
                .into_os_string()
                .into_string()
                .map_err(|_| invalid("non-UTF8 Store path"))?,
            fragment: fragment
                .into_os_string()
                .into_string()
                .map_err(|_| invalid("non-UTF8 unit fragment path"))?,
            uid,
            gid,
            start_us: micros(start_timeout)?,
            stop_us: micros(stop_timeout)?,
            restart: crate::execution::restart::ProcessRestart::Never,
        };
        context.validate()?;
        Ok(context)
    }
    pub(crate) fn with_restart(
        mut self,
        restart: crate::execution::restart::ProcessRestart,
    ) -> Result<Self> {
        self.restart = restart;
        self.validate()?;
        Ok(self)
    }
    pub(crate) const fn restart(&self) -> crate::execution::restart::ProcessRestart {
        self.restart
    }
    pub(super) fn validate(&self) -> Result<()> {
        path_text(Path::new(&self.store))?;
        path_text(Path::new(&self.fragment))?;
        if let Manager::User {
            bus_socket,
        } = &self.manager
        {
            path_text(Path::new(bus_socket))?;
        }
        if [self.uid, self.gid]
            .iter()
            .any(|value| *value == 0 || *value == u32::MAX)
            || self.start_us == 0
            || self.start_us > 300_000_000
            || self.stop_us == 0
            || self.stop_us > 60_000_000
        {
            return Err(invalid(
                "invalid operational identity or duration",
            ));
        }
        Ok(())
    }
    pub(crate) fn scope(&self) -> SystemdScope {
        match &self.manager {
            Manager::User {
                bus_socket,
            } => SystemdScope::User {
                bus_socket: bus_socket.into(),
            },
            Manager::System => SystemdScope::System,
        }
    }
    pub(crate) fn scope_key(&self) -> String {
        let bytes = serde_json::to_vec(&(&self.manager, self.uid, self.gid))
            .expect("fixed context serialization");
        format!(
            "syrox-os-scope-v1:{}",
            ContentDigest::sha256(&bytes)
        )
    }
    pub(crate) fn store(&self) -> &Path {
        Path::new(&self.store)
    }
    pub(crate) fn fragment(&self) -> &Path {
        Path::new(&self.fragment)
    }
    pub(crate) const fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) const fn gid(&self) -> u32 {
        self.gid
    }
    pub(crate) const fn start_timeout(&self) -> Duration {
        Duration::from_micros(self.start_us)
    }
    pub(crate) const fn stop_timeout(&self) -> Duration {
        Duration::from_micros(self.stop_us)
    }
}
fn micros(duration: Duration) -> Result<u64> {
    if !duration.subsec_nanos().is_multiple_of(1000) {
        return Err(invalid("duration is not whole microseconds"));
    }
    u64::try_from(duration.as_micros()).map_err(|_| invalid("duration exceeds limit"))
}

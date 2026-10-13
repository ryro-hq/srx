//! Comunicação local com o manager systemd, usando o cliente D-Bus da engine.
//!
//! Aceitar um job, concluir esse job e observar a unidade depois são resultados
//! diferentes. Se a conexão perder uma resposta, a operação reconecta e reconcilia
//! o estado antes de decidir o próximo passo. Uma mutação não é repetida só
//! porque a resposta faltou.
//!
//! O manager precisa de systemd >=250 para `ExitType=cgroup`. Builds Managed
//! precisam de >=254 para conferir a identidade dos descritores com
//! `DumpFileDescriptorStore`. Os pedidos usam o bus local escolhido e não pedem
//! autorização interativa.
//!
//! Frames têm limite de 1 MiB, headers de 16 KiB, textos de 4 KiB e jobs pendentes
//! de 64. As operações têm prazo máximo de 300 segundos; waits de socket,
//! autenticação e resposta observam cancelamento a cada 20 ms. O socket de
//! notificação trata FD store; transferência de FD/PTY por D-Bus não é implementada.
//!
//! Os formatos vêm da [especificação D-Bus](https://dbus.freedesktop.org/doc/dbus-specification.html)
//! e da [interface do manager](https://www.freedesktop.org/software/systemd/man/org.freedesktop.systemd1.html).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::cancellation::Cancellation;
use thiserror::Error;

#[allow(unsafe_code)]
mod bus;
#[allow(unsafe_code)]
mod notify;
pub use notify::{SystemdNotificationsProcessed, SystemdNotifier, SystemdNotifyEndpoint};
mod build;
pub(crate) mod fd_store;
pub(crate) mod loaded;
pub(crate) mod persistent;
mod properties;
pub(crate) mod quiescence;
mod service;
mod unit_reference;
mod wire;
pub use unit_reference::SystemdUnitReference;

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const MAX_TEXT: usize = 4096;
const MAX_JOBS: usize = 64;
const MAX_OPERATION: Duration = Duration::from_secs(300);
static CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Explicit local bus authority; never interprets remote/environment bus addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemdScope {
    User {
        bus_socket: PathBuf,
    },
    System,
}

impl SystemdScope {
    fn address(&self) -> Result<String, SystemdError> {
        let path = match self {
            Self::User {
                bus_socket,
            } => bus_socket.as_path(),
            Self::System => Path::new("/run/dbus/system_bus_socket"),
        };
        let text = absolute(path)?;
        let mut address = String::from("unix:path=");
        for byte in text.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.') {
                address.push(char::from(byte));
            } else {
                write!(address, "%{byte:02x}").expect("String write");
            }
        }
        Ok(address)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemdUnitName(String);
impl SystemdUnitName {
    pub fn new(name: impl Into<String>) -> Result<Self, SystemdError> {
        let name = name.into();
        if name.len() > 128
            || !name.starts_with("syrox-")
            || !name.ends_with(".service")
            || name.len() <= "syrox-.service".len()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(SystemdError::Invalid(
                "expected syrox-*.service unit name",
            ));
        }
        Ok(Self(name))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Manager lifecycle profile; notification senders must be the main process.
#[derive(Clone, Debug, Default)]
pub enum SystemdServiceProfile {
    #[default]
    Exec,
    Notify {
        fd_store_max: u32,
        start_timeout: Duration,
    },
}

/// Observation only: count does not establish the identity of retained descriptors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdFdStoreObserved {
    pub invocation: Vec<u8>,
    pub count: u32,
    pub max: u32,
    pub notify_access: String,
}

/// Explicit process credentials; requesting them does not grant permission to
/// transition identities or start a unit through the selected manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemdCredentials {
    pub uid: u32,
    pub gid: u32,
}

/// Additional build limits. Soft and hard process limits are set together;
/// swap and core dumps are disabled whenever this envelope is selected.
/// These requested limits do not establish that a manager has enforced them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemdBuildLimits {
    /// CPU percentage across all cores (100 means one CPU).
    pub cpu_percent: u32,
    pub nofile: u64,
    /// Maximum size in bytes of an individual file written by the process.
    pub file_size: u64,
}

#[derive(Clone, Debug)]
pub struct SystemdService {
    /// Manager restart policy; admission of each invocation remains the caller's responsibility.
    pub restart: crate::execution::restart::ProcessRestart,
    pub profile: SystemdServiceProfile,
    pub unit: SystemdUnitName,
    /// Adds `BindsTo` + `After` on a distinct Syrox unit. This is a manager
    /// dependency, not a session authorization: starting this unit may start
    /// its dependency. A launcher must separately reject revoked invocations.
    pub bound_to: Option<SystemdUnitName>,
    pub executable: PathBuf,
    /// Argumentos depois de `argv[0]`, sem expansão de shell ou ambiente.
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: Option<PathBuf>,
    pub runtime_max: Option<Duration>,
    pub stop_timeout: Duration,
    pub memory_max: Option<u64>,
    pub tasks_max: Option<u64>,
    pub build_limits: Option<SystemdBuildLimits>,
    pub credentials: Option<SystemdCredentials>,
}
impl SystemdService {
    pub fn new(unit: SystemdUnitName, executable: PathBuf) -> Self {
        Self {
            unit,
            profile: SystemdServiceProfile::Exec,
            restart: crate::execution::restart::ProcessRestart::Never,
            bound_to: None,
            executable,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            working_directory: None,
            runtime_max: None,
            stop_timeout: Duration::from_secs(2),
            memory_max: None,
            tasks_max: None,
            build_limits: None,
            credentials: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SystemdError {
    #[error("invalid systemd request: {0}")]
    Invalid(&'static str),
    #[error("systemd wait cancelled; no service stop is implied")]
    Cancelled,
    #[error("systemd operation deadline exceeded")]
    Deadline,
    #[error("systemd IPC failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid or oversized systemd reply: {0}")]
    Protocol(&'static str),
    #[error("systemd rejected request ({name}): {message}")]
    Remote {
        name: String,
        message: String,
    },
    #[error("systemd may have accepted a mutation for {unit}; reconcile before replay: {source}")]
    MutationUncertain {
        unit: String,
        source: Box<Self>,
    },
    #[error("systemd may have processed manager {operation}; reconcile before replay: {source}")]
    ManagerMutationUncertain {
        operation: &'static str,
        source: Box<Self>,
    },
}
impl SystemdError {
    fn absent_unit(&self) -> bool {
        matches!(self, Self::Remote { name, .. } if name == "org.freedesktop.systemd1.NoSuchUnit" || name == "org.freedesktop.DBus.Error.UnknownObject")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemdJobResult {
    Done,
    Cancelled,
    Timeout,
    Failed,
    Dependency,
    Skipped,
    Other(String),
}
impl SystemdJobResult {
    fn parse(text: String) -> Self {
        match text.as_str() {
            "done" => Self::Done,
            "canceled" => Self::Cancelled,
            "timeout" => Self::Timeout,
            "failed" => Self::Failed,
            "dependency" => Self::Dependency,
            "skipped" => Self::Skipped,
            _ => Self::Other(text),
        }
    }
}

/// A job path is evidence of acceptance only, not readiness or process success.
#[derive(Clone, Debug)]
pub struct SystemdJob {
    unit: SystemdUnitName,
    path: String,
    connection: u64,
}
impl SystemdJob {
    pub fn unit(&self) -> &SystemdUnitName {
        &self.unit
    }
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// A bounded observation. Properties can change between reads; no atomic snapshot
/// or cgroup-empty proof is claimed here. Invocation changes abort the observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdUnitStatus {
    pub unit: SystemdUnitName,
    pub invocation: Vec<u8>,
    pub active_state: String,
    pub sub_state: String,
    pub control_group: String,
    pub result: String,
    pub main_pid: u32,
    pub exec_main_code: i32,
    pub exec_main_status: i32,
}

#[derive(Clone, Debug)]
pub enum SystemdJobCompletion {
    Observed {
        result: SystemdJobResult,
    },
    /// A reconnect or missing job lost its completion signal. Unit state is only
    /// recovery evidence; it is never promoted to a successful job result.
    Unobserved {
        status: Option<SystemdUnitStatus>,
    },
}

#[derive(Debug)]
pub struct SystemdManager {
    scope: SystemdScope,
    bus: bus::Bus,
    connection: u64,
}

/// An observation of the bus instance and the manager's unique owner on it.
/// Callers must revalidate this observation before admitting a new invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdManagerIdentity {
    scope: SystemdScope,
    bus_guid: String,
    owner: String,
    fingerprint: crate::store::ContentDigest,
}
impl SystemdManagerIdentity {
    /// Controlled manager comparison data for tests with real process evidence.
    /// This does not claim that a running manager was observed.
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self::new(
            SystemdScope::System,
            "01".repeat(16),
            ":1.1".into(),
        )
        .expect("fixed test manager identity")
    }

    pub const fn scope(&self) -> &SystemdScope {
        &self.scope
    }
    pub fn bus_guid(&self) -> &str {
        &self.bus_guid
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub const fn fingerprint(&self) -> crate::store::ContentDigest {
        self.fingerprint
    }
    fn new(scope: SystemdScope, bus_guid: String, owner: String) -> Result<Self, SystemdError> {
        let bytes = format!(
            "syrox-systemd-manager-v1\n{}\n{bus_guid}\n{owner}\n",
            scope.address()?
        );
        let fingerprint = crate::store::ContentDigest::sha256(bytes.as_bytes());
        Ok(Self {
            scope,
            bus_guid,
            owner,
            fingerprint,
        })
    }
}
impl SystemdManager {
    pub fn connect(
        scope: SystemdScope,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Self, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let mut bus = bus::Bus::connect(&scope.address()?, &budget)?;
        let mut add_match = bus.method(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "AddMatch",
        )?;
        add_match.string("type='signal',sender='org.freedesktop.systemd1',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'")?;
        bus.call(add_match, &budget)?.expect_empty()?;
        let mut owner_call = bus.method(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
        )?;
        owner_call.string("org.freedesktop.systemd1")?;
        let owner = bus.call(owner_call, &budget)?.single_string()?;
        bus.set_owner(owner)?;
        let subscribe = bus.manager_method("Subscribe")?;
        bus.call(subscribe, &budget)?.expect_empty()?;
        Ok(Self {
            scope,
            bus,
            connection: CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Reconnect only; never replays a start/stop. Old job handles become unobserved.
    pub fn reconnect(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        *self = Self::connect(self.scope.clone(), timeout, cancellation)?;
        Ok(())
    }

    /// Query the well-known owner again and reject a changed manager. Reconnect
    /// remains explicit; a new bus or owner has a different fingerprint.
    pub fn observe_identity(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdManagerIdentity, SystemdError> {
        self.observe_identity_with(&Budget::new(timeout, cancellation)?)
    }

    fn observe_identity_with(
        &mut self,
        budget: &Budget<'_>,
    ) -> Result<SystemdManagerIdentity, SystemdError> {
        let mut call = self.bus.method(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
        )?;
        call.string("org.freedesktop.systemd1")?;
        let owner = match self
            .bus
            .call(call, budget)
            .and_then(|reply| reply.single_string())
        {
            Ok(owner) => owner,
            Err(error) => {
                self.bus.invalidate();
                return Err(error);
            }
        };
        self.bus.verify_manager_owner(&owner)?;
        budget.check()?;
        SystemdManagerIdentity::new(self.scope.clone(), self.bus.guid().into(), owner)
    }

    pub fn start_transient(
        &mut self,
        service: &SystemdService,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJob, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let properties = properties::service(service)?;
        let mut call = self.bus.manager_method("StartTransientUnit")?;
        call.string(service.unit.as_str())?;
        call.string("fail")?;
        call.properties(&properties)?;
        call.empty_array("(sa(sv))")?;
        self.bus.watch(service.unit.as_str())?;
        self.mutate(call, &service.unit, &budget)
    }

    /// Enqueue activation of a unit loaded from the manager's unit search path.
    /// Uses `fail` mode: conflicting jobs are never replaced. Acceptance is not
    /// readiness, and even a `Done` job may mean a condition skipped activation.
    /// This does not authenticate persistent unit bytes or authorize their effects.
    pub fn start_unit(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJob, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let call = self
            .bus
            .manager_unit_job("StartUnit", unit.as_str(), "fail")?;
        self.bus.watch(unit.as_str())?;
        self.mutate(call, unit, &budget)
    }

    /// Request `Manager.Reload` and observe its empty method reply. This reloads
    /// unit definitions, not service processes; there is no unit job to await.
    /// The reply does not prove a particular unit-file fingerprint was installed.
    /// A lost reply is uncertain and must be reconciled without automatic replay.
    pub fn reload(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let call = self.bus.manager_method("Reload")?;
        budget.check()?;
        match self
            .bus
            .call(call, &budget)
            .and_then(|reply| reply.expect_empty())
        {
            Ok(()) => Ok(()),
            Err(
                error @ SystemdError::Remote {
                    ..
                },
            ) => Err(error),
            Err(source) => {
                self.bus.invalidate();
                Err(SystemdError::ManagerMutationUncertain {
                    operation: "Reload",
                    source: Box::new(source),
                })
            }
        }
    }

    pub fn stop(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJob, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let call = self
            .bus
            .manager_unit_job("StopUnit", unit.as_str(), "replace")?;
        self.bus.watch(unit.as_str())?;
        self.mutate(call, unit, &budget)
    }

    fn mutate(
        &mut self,
        message: bus::Message,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<SystemdJob, SystemdError> {
        if let Err(error) = budget.check() {
            self.bus.release(unit.as_str());
            return Err(error);
        }
        let request = self
            .bus
            .call(message, budget)
            .and_then(|mut reply| reply.single_object());
        match request {
            Ok(path) if valid_job_path(&path) => {
                self.bus.register_job(&path, unit.as_str());
                Ok(SystemdJob {
                    unit: unit.clone(),
                    path,
                    connection: self.connection,
                })
            }
            Ok(_) => {
                self.bus.release(unit.as_str());
                Err(SystemdError::MutationUncertain {
                    unit: unit.0.clone(),
                    source: Box::new(SystemdError::Protocol("invalid job path")),
                })
            }
            Err(
                error @ SystemdError::Remote {
                    ..
                },
            ) => {
                self.bus.release(unit.as_str());
                Err(error)
            }
            Err(error) => {
                self.bus.release(unit.as_str());
                Err(SystemdError::MutationUncertain {
                    unit: unit.0.clone(),
                    source: Box::new(error),
                })
            }
        }
    }

    pub fn query(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Option<SystemdUnitStatus>, SystemdError> {
        self.query_with(unit, &Budget::new(timeout, cancellation)?)
    }

    /// A bounded observation across a stable invocation, never a lease identity proof.
    pub fn query_fd_store(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<Option<SystemdFdStoreObserved>, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(unit.as_str())?;
        let path = match self
            .bus
            .call(call, &budget)
            .and_then(|mut reply| reply.single_object())
        {
            Ok(path) => path,
            Err(error) if error.absent_unit() => return Ok(None),
            Err(error) => return Err(error),
        };
        if !path.starts_with("/org/freedesktop/systemd1/unit/") {
            return Err(SystemdError::Protocol("invalid unit path"));
        }
        let invocation = self
            .bus
            .get_bytes(&path, UNIT_INTERFACE, "InvocationID", &budget)?;
        if !invocation.is_empty() && invocation.len() != 16 {
            return Err(SystemdError::Protocol(
                "invalid invocation identifier",
            ));
        }
        let observed = SystemdFdStoreObserved {
            invocation,
            count: self.bus.get_u32(
                &path,
                SERVICE_INTERFACE,
                "NFileDescriptorStore",
                &budget,
            )?,
            max: self.bus.get_u32(
                &path,
                SERVICE_INTERFACE,
                "FileDescriptorStoreMax",
                &budget,
            )?,
            notify_access: self.bus.get_string(
                &path,
                SERVICE_INTERFACE,
                "NotifyAccess",
                &budget,
            )?,
        };
        if observed.invocation
            != self
                .bus
                .get_bytes(&path, UNIT_INTERFACE, "InvocationID", &budget)?
        {
            return Err(SystemdError::Protocol(
                "invocation changed during observation",
            ));
        }
        Ok(Some(observed))
    }

    fn query_with(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<SystemdUnitStatus>, SystemdError> {
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(unit.as_str())?;
        let path = match self
            .bus
            .call(call, budget)
            .and_then(|mut reply| reply.single_object())
        {
            Ok(path) => path,
            Err(error) if error.absent_unit() => return Ok(None),
            Err(error) => return Err(error),
        };
        if !path.starts_with("/org/freedesktop/systemd1/unit/") {
            return Err(SystemdError::Protocol("invalid unit path"));
        }
        let observe = (|| {
            let invocation = self
                .bus
                .get_bytes(&path, UNIT_INTERFACE, "InvocationID", budget)?;
            if !invocation.is_empty() && invocation.len() != 16 {
                return Err(SystemdError::Protocol(
                    "invalid invocation identifier",
                ));
            }
            let status = SystemdUnitStatus {
                unit: unit.clone(),
                invocation,
                active_state: self
                    .bus
                    .get_string(&path, UNIT_INTERFACE, "ActiveState", budget)?,
                sub_state: self
                    .bus
                    .get_string(&path, UNIT_INTERFACE, "SubState", budget)?,
                control_group: self.bus.get_string(
                    &path,
                    SERVICE_INTERFACE,
                    "ControlGroup",
                    budget,
                )?,
                result: self
                    .bus
                    .get_string(&path, SERVICE_INTERFACE, "Result", budget)?,
                main_pid: self
                    .bus
                    .get_u32(&path, SERVICE_INTERFACE, "MainPID", budget)?,
                exec_main_code: self.bus.get_i32(
                    &path,
                    SERVICE_INTERFACE,
                    "ExecMainCode",
                    budget,
                )?,
                exec_main_status: self.bus.get_i32(
                    &path,
                    SERVICE_INTERFACE,
                    "ExecMainStatus",
                    budget,
                )?,
            };
            if self
                .bus
                .get_bytes(&path, UNIT_INTERFACE, "InvocationID", budget)?
                != status.invocation
            {
                return Err(SystemdError::Protocol(
                    "unit invocation changed during observation",
                ));
            }
            Ok(status)
        })();
        match observe {
            Ok(status) => Ok(Some(status)),
            Err(error) if error.absent_unit() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Bounded idle observation only; this establishes neither ownership nor
    /// cgroup quiescence and does not reserve the unit against future activation.
    pub(crate) fn unit_idle_without_job(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<bool, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let before = self.observe_identity_with(&budget)?;
        let first = self.idle_snapshot(unit, &budget)?;
        let second = self.idle_snapshot(unit, &budget)?;
        if self.observe_identity_with(&budget)? != before {
            return Err(SystemdError::Protocol(
                "manager changed during idle observation",
            ));
        }
        Ok(first == second && first.as_ref().is_none_or(UnitIdleSnapshot::idle))
    }
    fn idle_snapshot(
        &mut self,
        unit: &SystemdUnitName,
        budget: &Budget<'_>,
    ) -> Result<Option<UnitIdleSnapshot>, SystemdError> {
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(unit.as_str())?;
        let path = strict_unit_path(
            self.bus
                .call(call, budget)
                .and_then(|mut reply| reply.single_object()),
        )?;
        let Some(path) = path else {
            return Ok(None);
        };
        let name = self
            .bus
            .get_string(&path, UNIT_INTERFACE, "Id", budget)?;
        if name != unit.as_str() {
            return Err(SystemdError::Protocol(
                "idle unit identity differs",
            ));
        }
        let active = self
            .bus
            .get_string(&path, UNIT_INTERFACE, "ActiveState", budget)?;
        let job = self.bus.get_unit_job(&path, budget)?;
        Ok(Some(UnitIdleSnapshot {
            path,
            active,
            job,
        }))
    }

    /// Observe whether a recorded job has left this manager's job table.
    /// Absence does not establish successful completion or a `JobRemoved` result.
    pub(crate) fn recorded_job_absent(
        &mut self,
        path: &str,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<bool, SystemdError> {
        let id = job_id(path).ok_or(SystemdError::Protocol(
            "invalid recorded job identity",
        ))?;
        let budget = Budget::new(timeout, cancellation)?;
        let before = self.observe_identity_with(&budget)?;
        let mut call = self.bus.manager_method("GetJob")?;
        call.u32(id);
        let reply = self
            .bus
            .call(call, &budget)
            .and_then(|mut reply| reply.single_object());
        let absent = recorded_job_reply(path, reply)?;
        if self.observe_identity_with(&budget)? != before {
            return Err(SystemdError::Protocol(
                "manager identity changed during job observation",
            ));
        }
        Ok(absent)
    }

    /// Cancellation stops this wait only. Use a distinct cleanup operation/token
    /// to stop the unit and separately observe its stop job.
    pub fn wait_job(
        &mut self,
        job: &SystemdJob,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<SystemdJobCompletion, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        if job.connection != self.connection {
            return Ok(SystemdJobCompletion::Unobserved {
                status: self.query_with(&job.unit, &budget)?,
            });
        }
        loop {
            budget.check()?;
            if let Some(event) = self.bus.take_job(&job.path) {
                if event.unit != job.unit.as_str() {
                    return Err(SystemdError::Protocol("job unit mismatch"));
                }
                self.bus.release_job(&job.path);
                return Ok(SystemdJobCompletion::Observed {
                    result: SystemdJobResult::parse(event.result),
                });
            }
            // A disappeared job without its signal is not assumed successful.
            let mut call = self.bus.manager_method("GetJob")?;
            call.u32(job_id(&job.path).ok_or(SystemdError::Protocol("invalid job identity"))?);
            match self.bus.call(call, &budget) {
                Ok(mut reply) => {
                    if reply.single_object()? != job.path {
                        return Err(SystemdError::Protocol("job identity changed"));
                    }
                }
                Err(SystemdError::Remote {
                    name,
                    ..
                }) if name == "org.freedesktop.systemd1.NoSuchJob" => {
                    if self.bus.has_job(&job.path) {
                        continue;
                    }
                    self.bus.release_job(&job.path);
                    return Ok(SystemdJobCompletion::Unobserved {
                        status: self.query_with(&job.unit, &budget)?,
                    });
                }
                Err(error) => return Err(error),
            }
            self.bus.pump(&budget)?;
        }
    }
}

#[derive(PartialEq, Eq)]
struct UnitIdleSnapshot {
    path: String,
    active: String,
    job: (u32, String),
}
impl UnitIdleSnapshot {
    fn idle(&self) -> bool {
        matches!(self.active.as_str(), "inactive" | "failed")
            && self.job.0 == 0
            && self.job.1 == "/"
    }
}
fn strict_unit_path(reply: Result<String, SystemdError>) -> Result<Option<String>, SystemdError> {
    match reply {
        Ok(path)
            if path
                .strip_prefix("/org/freedesktop/systemd1/unit/")
                .is_some_and(|tail| {
                    !tail.is_empty()
                        && tail
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                }) =>
        {
            Ok(Some(path))
        }
        Ok(_) => Err(SystemdError::Protocol("invalid idle unit path")),
        Err(SystemdError::Remote {
            name,
            ..
        }) if name == "org.freedesktop.systemd1.NoSuchUnit" => Ok(None),
        Err(error) => Err(error),
    }
}

fn recorded_job_reply(
    path: &str,
    reply: Result<String, SystemdError>,
) -> Result<bool, SystemdError> {
    match reply {
        Ok(observed) if observed == path => Ok(false),
        Ok(_) => Err(SystemdError::Protocol(
            "recorded job identity changed",
        )),
        Err(SystemdError::Remote {
            name,
            ..
        }) if name == "org.freedesktop.systemd1.NoSuchJob" => Ok(true),
        Err(error) => Err(error),
    }
}

fn job_id(path: &str) -> Option<u32> {
    let id = path.strip_prefix("/org/freedesktop/systemd1/job/")?;
    let parsed: u32 = id.parse().ok()?;
    (parsed != 0 && parsed.to_string() == id).then_some(parsed)
}
pub(crate) fn valid_job_path(path: &str) -> bool {
    job_id(path).is_some()
}

fn text(value: &str) -> Result<(), SystemdError> {
    if value.len() > MAX_TEXT || value.as_bytes().contains(&0) {
        Err(SystemdError::Invalid("text length or NUL"))
    } else {
        Ok(())
    }
}
fn absolute(path: &Path) -> Result<&str, SystemdError> {
    let value = path
        .to_str()
        .ok_or(SystemdError::Invalid("path must be UTF-8"))?;
    text(value)?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(SystemdError::Invalid(
            "expected absolute path without traversal",
        ));
    }
    Ok(value)
}

struct Budget<'a> {
    end: Instant,
    cancellation: &'a Cancellation,
}
impl<'a> Budget<'a> {
    fn new(timeout: Duration, cancellation: &'a Cancellation) -> Result<Self, SystemdError> {
        if timeout.is_zero() || timeout > MAX_OPERATION {
            return Err(SystemdError::Invalid(
                "deadline must be in (0, 300s]",
            ));
        }
        let budget = Self {
            end: Instant::now() + timeout,
            cancellation,
        };
        budget.check()?;
        Ok(budget)
    }
    fn check(&self) -> Result<(), SystemdError> {
        self.cancellation
            .check()
            .map_err(|_| SystemdError::Cancelled)?;
        if Instant::now() >= self.end {
            Err(SystemdError::Deadline)
        } else {
            Ok(())
        }
    }
    fn remaining_us(&self) -> Result<u64, SystemdError> {
        self.check()?;
        Ok(u64::try_from(
            self.end
                .saturating_duration_since(Instant::now())
                .as_micros(),
        )
        .unwrap_or(u64::MAX)
        .max(1))
    }
}

#[cfg(test)]
mod tests;

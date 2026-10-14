use super::{
    AuthorityState, Pump, Role, ServiceAuthority, ServiceError, ServiceOwner, ServiceRoleStart,
};
use crate::execution::journal::roles::retention::RoleRetentionIdentity;
use crate::execution::journal::{RoleBinding, SessionJournal};
use crate::execution::launcher::service_coordinator::{remaining, settlement, validate_role};
use crate::{
    cancellation::Cancellation, systemd::SystemdManager, systemd::SystemdScope,
    systemd::SystemdService, systemd::SystemdServiceProfile, systemd::SystemdUnitName,
};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub(super) fn prepare(
    owner: Arc<ServiceOwner>,
    journal: Arc<SessionJournal>,
    starts: Vec<ServiceRoleStart>,
    directory: &Path,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<Pump, ServiceError> {
    let mut names = BTreeSet::new();
    for start in &starts {
        validate_role(&start.role)?;
        if !names.insert(&start.role) {
            return Err(ServiceError::State("duplicate service role"));
        }
    }
    if starts.len() >= crate::execution::journal::MAX_SESSION_ATTEMPTS {
        return Err(ServiceError::State(
            "service role capacity exceeded",
        ));
    }
    let mut manager = SystemdManager::connect(
        SystemdScope::User {
            bus_socket: owner.bus.clone(),
        },
        remaining(deadline)?,
        cancel,
    )?;
    let epoch = manager.observe_identity(remaining(deadline)?, cancel)?;
    let mut roles = Vec::new();
    for start in starts {
        let first = journal.prepare_attempt(&owner.session, &start.role, cancel, deadline)?;
        let unit = SystemdUnitName::new(format!(
            "syrox-service-{}.service",
            first.as_str()
        ))?;
        let binding = RoleBinding::new(
            owner.session.clone(),
            &start.role,
            owner.manifest,
            start.prepared.spec.digest()?,
            unit.clone(),
            owner.binding.clone(),
            start.restart,
        )?;
        let owner_alive = settlement::observe_live_owner(&owner, &mut manager, cancel, deadline)?;
        journal.register_role(&binding, &first, &owner_alive, cancel, deadline)?;
        let resources = start.prepared.into_reusable()?;
        let (pin, store_anchor) = resources.retention_identity()?;
        let retention = RoleRetentionIdentity::new(first.clone(), pin, store_anchor);
        // Record the exact Store and retained set before publication. Recovery
        // can distinguish an unfinished intent from a confirmed publication.
        journal.begin_role_retention(
            &binding,
            &retention,
            &owner_alive,
            cancel,
            deadline,
        )?;
        let hold = resources.persist_role(first.as_str(), cancel)?;
        journal.confirm_role_retention(&binding, &hold, &owner_alive, cancel, deadline)?;
        let mut listener = crate::execution::launcher::rendezvous::Listener::bind(
            directory,
            &format!("service-{first}.sock"),
        )?;
        listener.preserve_on_drop();
        let service = service(&owner, &binding, listener.path())?;
        roles.push(Role {
            binding,
            first,
            listener,
            service,
            resources,
            hold: Some(hold),
            history: Vec::new(),
            pending: super::super::ServicePending::default(),
            retirement_uncertain: false,
            uncertain: false,
            observed: None,
        });
    }
    let authority = ServiceAuthority {
        state: Arc::new(AuthorityState {
            healthy: AtomicBool::new(true),
            uncertain: AtomicBool::new(!roles.is_empty()),
            processes: std::sync::Mutex::new(Vec::new()),
            roles: roles
                .iter()
                .map(|role| role.binding.clone())
                .collect(),
        }),
    };
    Ok(Pump {
        owner,
        journal,
        manager,
        epoch,
        roles,
        authority,
    })
}
fn service(
    owner: &ServiceOwner,
    role: &RoleBinding,
    endpoint: &Path,
) -> Result<SystemdService, ServiceError> {
    let mut service = SystemdService::new(role.unit().clone(), owner.worker.clone());
    service.bound_to = Some(owner.binding.unit().clone());
    service.profile = SystemdServiceProfile::Notify {
        fd_store_max: 1,
        start_timeout: super::super::pending::START_TIMEOUT,
    };
    service.restart = role.restart();
    let mut invocation = String::with_capacity(32);
    for byte in owner.binding.invocation() {
        write!(&mut invocation, "{byte:02x}").expect("string");
    }
    service.arguments = vec![
        "__service".into(),
        endpoint
            .to_str()
            .ok_or(ServiceError::State("service endpoint UTF-8"))?
            .into(),
        owner.session.to_string(),
        role.digest().to_string(),
        owner.manifest.to_string(),
        role.command().to_string(),
        role.unit().as_str().into(),
        owner.binding.unit().as_str().into(),
        invocation,
    ];
    Ok(service)
}

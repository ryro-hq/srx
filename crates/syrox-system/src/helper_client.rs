//! Unprivileged coordinator client for the explicitly selected root scratch helper.
//!
//! Control stays in the coordinator's identity namespace; only the scratch root
//! is handed to the isolated worker. No implicit reconnect, release, recovery,
//! reformat or installation occurs. Dropping an unsettled lease closes its
//! connection and leaves the helper to journal uncertainty.

use crate::{
    budget::{AdmittedBudget, BuildBudget},
    helper_protocol::Request,
    scratch::{ReceivedScratch, ScratchCapacity},
};
use std::fs::File;
use std::io;
use std::path::Path;
use std::time::Instant;

mod connection;
mod workspace;
pub use workspace::{WorkspaceGrant, WorkspaceLease};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct HelperClient {
    connection: connection::Connection,
}

#[derive(Debug)]
pub struct ScratchGrant {
    root: File,
    lease: ScratchLease,
    capacity: ScratchCapacity,
}

#[derive(Debug)]
pub struct ScratchLease {
    connection: connection::Connection,
    id: String,
    authorization: String,
    budget: BuildBudget,
}

/// Authenticated inspection and its explicit authorization hash. The complete
/// plan is retained for review; it is never automatically applied on failure.
#[derive(Debug)]
pub struct RecoveryInspection {
    pub plan: serde_json::Value,
    pub plan_sha256: String,
}

impl HelperClient {
    /// Connect to a protected root-owned activation socket in the coordinator's
    /// full identity namespace. Backlog failure returns without a request/retry.
    pub fn connect(
        endpoint: &Path,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<Self> {
        Ok(Self {
            connection: connection::Connection::connect(endpoint, &mut check, deadline)?,
        })
    }

    /// Root policy independently admits the request. The caller's pure budget
    /// token does not replace that policy or authorize any other system effect.
    pub fn prepare(
        self,
        id: &str,
        budget: &AdmittedBudget,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<ScratchGrant> {
        validate_id(id)?;
        self.connection.send(
            &Request::Prepare {
                version: 1,
                id: id.into(),
                budget: *budget.request(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "offered", id)?;
        let authorization = hash(&details["authorization"])?;
        let offered_budget: BuildBudget = serde_json::from_value(details["budget"].clone())?;
        if offered_budget != *budget.request() {
            return Err(invalid("helper offered a different build budget"));
        }
        let root = File::from(self.connection.receive(&mut check, deadline)?);
        let verified = ReceivedScratch::from_authorized_root(root.try_clone()?, budget)?;
        let capacity = verified.capacity();
        if details["filesystem_bytes"].as_u64() != Some(capacity.filesystem_bytes)
            || details["inodes"].as_u64() != Some(capacity.inodes)
        {
            return Err(invalid(
                "helper receipt and received filesystem geometry differ",
            ));
        }
        Ok(ScratchGrant {
            root,
            capacity,
            lease: ScratchLease {
                connection: self.connection,
                id: id.into(),
                authorization,
                budget: offered_budget,
            },
        })
    }

    pub fn inspect(
        self,
        id: &str,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<RecoveryInspection> {
        validate_id(id)?;
        self.connection.send(
            &Request::Inspect {
                version: 1,
                id: id.into(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let plan = &response["plan"];
        if response["version"] != 1
            || plan["version"] != 1
            || plan["id"] != id
            || !matches!(
                plan["action"].as_str(),
                Some("blocked" | "reconcile-retained-image")
            )
            || plan["image_retained"] != true
            || plan["filesystem_health_verified"] != false
        {
            return Err(invalid(
                "unsupported or inconsistent scratch recovery inspection",
            ));
        }
        Ok(RecoveryInspection {
            plan: plan.clone(),
            plan_sha256: hash(&response["plan_sha256"])?,
        })
    }

    /// Apply only an explicitly reviewed hash; the server reobserves its state
    /// and refuses blocked/stale plans before appending the reconciliation.
    pub fn recover(
        self,
        id: &str,
        plan_sha256: &str,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<serde_json::Value> {
        validate_id(id)?;
        validate_hash(plan_sha256)?;
        self.connection.send(
            &Request::Recover {
                version: 1,
                id: id.into(),
                plan_sha256: plan_sha256.into(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "reconciled", id)?;
        if details["plan_sha256"] != plan_sha256
            || details["image_retained"] != true
            || details["filesystem_health_verified"] != false
        {
            return Err(invalid(
                "helper reconciliation receipt differs from the authorized plan",
            ));
        }
        Ok(response)
    }
}

impl ScratchGrant {
    pub const fn capacity(&self) -> ScratchCapacity {
        self.capacity
    }
    /// Keep the lease/control outside worker namespaces. All root/file copies
    /// and the worker namespace must end before explicitly releasing the lease.
    pub fn into_parts(self) -> (File, ScratchLease) {
        (self.root, self.lease)
    }
}

impl ScratchLease {
    pub const fn budget(&self) -> &BuildBudget {
        &self.budget
    }

    pub fn release(
        self,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<serde_json::Value> {
        self.connection.send(
            &Request::Release {
                version: 1,
                id: self.id.clone(),
                authorization: self.authorization.clone(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "released", &self.id)?;
        if details["authorization"] != self.authorization || details["image_retained"] != true {
            return Err(invalid(
                "helper release receipt differs from the scratch authorization",
            ));
        }
        Ok(response)
    }
}

fn record<'a>(
    value: &'a serde_json::Value,
    state: &str,
    id: &str,
) -> io::Result<&'a serde_json::Value> {
    if value["version"] != 1 || value["state"] != state || value["details"]["id"] != id {
        return Err(invalid(
            "unexpected helper journal receipt version, state or operation",
        ));
    }
    Ok(&value["details"])
}

fn hash(value: &serde_json::Value) -> io::Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid("missing helper authorization hash"))?;
    validate_hash(text)?;
    Ok(text.into())
}

fn validate_id(id: &str) -> io::Result<()> {
    validate_hex(id, 32)
}
fn validate_hash(hash: &str) -> io::Result<()> {
    validate_hex(hash, 64)
}
fn validate_hex(value: &str, length: usize) -> io::Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused(
            "helper identifiers and hashes require canonical lowercase hex",
        ));
    }
    Ok(())
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn refused(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
